"""
Path: infrastructure/source/api/services/storage.py
Version: 2 - STREAMING & MEMORY OPTIMIZATIONS
"""

import logging
import hashlib
import tempfile
import zipfile
import json
import asyncio
from typing import Optional, Dict, Any, BinaryIO, List, AsyncIterator
from datetime import datetime, timezone, timedelta
from pathlib import Path
from io import BytesIO
import aiofiles

# OPTIMIZED: Use async MinIO client for better performance
from minio import Minio
from minio.error import S3Error
from concurrent.futures import ThreadPoolExecutor

from .interfaces import StorageServiceInterface
from ..models.base import FileInfoModel
from ..config import get_settings

logger = logging.getLogger(__name__)
settings = get_settings()

# OPTIMIZED: Global thread pool for I/O operations
_io_thread_pool: Optional[ThreadPoolExecutor] = None


def get_io_thread_pool() -> ThreadPoolExecutor:
    """Get shared thread pool for I/O operations"""
    global _io_thread_pool
    if _io_thread_pool is None:
        _io_thread_pool = ThreadPoolExecutor(
            max_workers=min(10, (settings.mongodb_max_connections // 2)),  # Reasonable limit
            thread_name_prefix="storage_io"
        )
    return _io_thread_pool


class StorageService(StorageServiceInterface):
    """Production storage service using MinIO/S3 with streaming optimizations"""
    
    def __init__(
        self,
        endpoint: str,
        access_key: str,
        secret_key: str,
        secure: bool = True,
        bucket_name: str = "opendocseal-documents",
        region: str = "us-east-1",
        test_hooks=None
    ):
        self.endpoint = endpoint
        self.access_key = access_key
        self.secret_key = secret_key
        self.secure = secure
        self.bucket_name = bucket_name
        self.region = region
        self.test_hooks = test_hooks
        
        # OPTIMIZED: Connection pool settings for better performance
        self.client = Minio(
            endpoint=self.endpoint,
            access_key=self.access_key,
            secret_key=self.secret_key,
            secure=self.secure,
            region=self.region,
            http_client=self._create_optimized_http_client()
        )
        
        # Ensure bucket exists
        asyncio.create_task(self._ensure_bucket_exists_async())
        
        # OPTIMIZED: Streaming configuration
        self.chunk_size = 8 * 1024 * 1024  # 8MB chunks for streaming
        self.memory_limit = 50 * 1024 * 1024  # 50MB - switch to streaming above this
    
    def _create_optimized_http_client(self):
        """Create optimized HTTP client for MinIO"""
        try:
            import urllib3
            # OPTIMIZED: Connection pool settings
            return urllib3.PoolManager(
                timeout=urllib3.Timeout(connect=10, read=60),  # Reasonable timeouts
                maxsize=20,  # Connection pool size
                retries=urllib3.Retry(total=3, backoff_factor=0.5)  # Retry logic
            )
        except ImportError:
            # Fallback to default if urllib3 not available
            return None
    
    async def _ensure_bucket_exists_async(self):
        """Ensure the storage bucket exists (async wrapper)"""
        loop = asyncio.get_event_loop()
        thread_pool = get_io_thread_pool()
        
        try:
            await loop.run_in_executor(thread_pool, self._ensure_bucket_exists)
        except Exception as e:
            logger.error(f"Failed to ensure bucket exists: {e}")
    
    def _ensure_bucket_exists(self):
        """Ensure the storage bucket exists (sync version for thread pool)"""
        try:
            if not self.client.bucket_exists(self.bucket_name):
                self.client.make_bucket(self.bucket_name, location=self.region)
                logger.info(f"Created storage bucket: {self.bucket_name}")
            else:
                logger.debug(f"Storage bucket exists: {self.bucket_name}")
                
        except S3Error as e:
            logger.error(f"Failed to ensure bucket exists: {e}")
            raise
    
    async def store_file(
        self,
        file_data: BinaryIO,
        file_path: str,
        content_type: str = "application/octet-stream",
        metadata: Optional[Dict[str, str]] = None
    ) -> str:
        """OPTIMIZED: Store file with streaming for large files"""
        try:
            # OPTIMIZED: Get file size without reading entire content
            current_pos = file_data.tell()
            file_data.seek(0, 2)  # Seek to end
            file_size = file_data.tell()
            file_data.seek(current_pos)  # Restore position
            
            # OPTIMIZED: Choose strategy based on file size
            if file_size <= self.memory_limit:
                # Small files: use memory approach for speed
                return await self._store_file_memory(file_data, file_path, content_type, metadata, file_size)
            else:
                # Large files: use streaming approach for memory efficiency
                return await self._store_file_streaming(file_data, file_path, content_type, metadata, file_size)
            
        except Exception as e:
            logger.error(f"Failed to store file: {e}")
            raise
    
    async def _store_file_memory(
        self,
        file_data: BinaryIO,
        file_path: str,
        content_type: str,
        metadata: Optional[Dict[str, str]],
        file_size: int
    ) -> str:
        """Store small file using memory approach"""
        try:
            # Read file content
            file_data.seek(0)
            content = file_data.read()
            
            # Calculate hash
            file_hash = hashlib.sha256(content).hexdigest()
            
            # Prepare metadata
            object_metadata = self._prepare_metadata(content_type, file_hash, file_size, metadata)
            
            # Store using thread pool
            loop = asyncio.get_event_loop()
            thread_pool = get_io_thread_pool()
            
            result = await loop.run_in_executor(
                thread_pool,
                self._sync_put_object,
                BytesIO(content),
                file_path,
                file_size,
                content_type,
                object_metadata
            )
            
            # Capture test event
            if self.test_hooks:
                await self.test_hooks.capture_event(
                    "storage", "file_stored",
                    {
                        "file_path": file_path,
                        "file_size": file_size,
                        "file_hash": file_hash,
                        "method": "memory",
                        "etag": result.etag
                    }
                )
            
            logger.info(f"File stored (memory): {file_path} ({file_size} bytes)")
            return file_path
            
        except Exception as e:
            logger.error(f"Failed to store file via memory: {e}")
            raise
    
    async def _store_file_streaming(
        self,
        file_data: BinaryIO,
        file_path: str,
        content_type: str,
        metadata: Optional[Dict[str, str]],
        file_size: int
    ) -> str:
        """OPTIMIZED: Store large file using streaming approach"""
        try:
            # OPTIMIZED: Use temporary file for streaming large files
            with tempfile.NamedTemporaryFile() as temp_file:
                # Stream file content and calculate hash
                file_hash = hashlib.sha256()
                file_data.seek(0)
                
                # Copy data in chunks while calculating hash
                while True:
                    chunk = file_data.read(self.chunk_size)
                    if not chunk:
                        break
                    temp_file.write(chunk)
                    file_hash.update(chunk)
                
                temp_file.flush()
                temp_file.seek(0)
                
                # Prepare metadata
                object_metadata = self._prepare_metadata(
                    content_type, file_hash.hexdigest(), file_size, metadata
                )
                
                # Store using thread pool with streaming
                loop = asyncio.get_event_loop()
                thread_pool = get_io_thread_pool()
                
                result = await loop.run_in_executor(
                    thread_pool,
                    self._sync_put_object,
                    temp_file,
                    file_path,
                    file_size,
                    content_type,
                    object_metadata
                )
                
                # Capture test event
                if self.test_hooks:
                    await self.test_hooks.capture_event(
                        "storage", "file_stored",
                        {
                            "file_path": file_path,
                            "file_size": file_size,
                            "file_hash": file_hash.hexdigest(),
                            "method": "streaming",
                            "etag": result.etag
                        }
                    )
                
                logger.info(f"File stored (streaming): {file_path} ({file_size} bytes)")
                return file_path
            
        except Exception as e:
            logger.error(f"Failed to store file via streaming: {e}")
            raise
    
    def _sync_put_object(self, file_data, file_path, file_size, content_type, metadata):
        """Synchronous put_object for thread pool execution"""
        return self.client.put_object(
            bucket_name=self.bucket_name,
            object_name=file_path,
            data=file_data,
            length=file_size,
            content_type=content_type,
            metadata=metadata
        )
    
    def _prepare_metadata(
        self,
        content_type: str,
        file_hash: str,
        file_size: int,
        metadata: Optional[Dict[str, str]]
    ) -> Dict[str, str]:
        """Prepare object metadata"""
        object_metadata = {
            "Content-Type": content_type,
            "X-File-Hash": file_hash,
            "X-File-Size": str(file_size),
            "X-Upload-Time": datetime.now(timezone.utc).isoformat()
        }
        
        if metadata:
            # Prefix user metadata to avoid conflicts
            for key, value in metadata.items():
                object_metadata[f"X-Meta-{key}"] = str(value)[:1024]  # Limit metadata size
        
        return object_metadata
    
    async def get_file(self, file_path: str) -> Optional[BinaryIO]:
        """OPTIMIZED: Retrieve file with streaming support"""
        try:
            # Check file info first to determine size
            file_info = await self.get_file_info(file_path)
            if not file_info:
                return None
            
            # OPTIMIZED: Choose strategy based on file size
            if file_info.size <= self.memory_limit:
                return await self._get_file_memory(file_path)
            else:
                # For large files, return a streaming BytesIO
                return await self._get_file_streaming(file_path)
            
        except Exception as e:
            logger.error(f"Failed to retrieve file: {e}")
            raise
    
    async def _get_file_memory(self, file_path: str) -> Optional[BinaryIO]:
        """Get small file using memory approach"""
        try:
            loop = asyncio.get_event_loop()
            thread_pool = get_io_thread_pool()
            
            response = await loop.run_in_executor(
                thread_pool,
                self.client.get_object,
                self.bucket_name,
                file_path
            )
            
            # OPTIMIZED: Read in memory for small files
            content = response.read()
            response.close()
            response.release_conn()
            
            # Capture test event
            if self.test_hooks:
                await self.test_hooks.capture_event(
                    "storage", "file_retrieved",
                    {"file_path": file_path, "method": "memory", "size": len(content)}
                )
            
            logger.debug(f"File retrieved (memory): {file_path}")
            return BytesIO(content)
            
        except S3Error as e:
            if e.code == "NoSuchKey":
                logger.warning(f"File not found: {file_path}")
                return None
            else:
                logger.error(f"Failed to retrieve file: {e}")
                raise
    
    async def _get_file_streaming(self, file_path: str) -> Optional[BinaryIO]:
        """OPTIMIZED: Get large file using streaming approach with temp file"""
        try:
            loop = asyncio.get_event_loop()
            thread_pool = get_io_thread_pool()
            
            # Create temporary file for streaming
            temp_file = tempfile.NamedTemporaryFile(delete=False)
            
            try:
                # Stream download to temp file
                await loop.run_in_executor(
                    thread_pool,
                    self._sync_stream_download,
                    file_path,
                    temp_file
                )
                
                # Reopen temp file for reading
                temp_file.seek(0)
                
                # Create a BytesIO with the content
                content = temp_file.read()
                temp_file.close()
                
                # Clean up temp file
                Path(temp_file.name).unlink(missing_ok=True)
                
                # Capture test event
                if self.test_hooks:
                    await self.test_hooks.capture_event(
                        "storage", "file_retrieved",
                        {"file_path": file_path, "method": "streaming", "size": len(content)}
                    )
                
                logger.debug(f"File retrieved (streaming): {file_path}")
                return BytesIO(content)
                
            except Exception as e:
                # Clean up temp file on error
                temp_file.close()
                Path(temp_file.name).unlink(missing_ok=True)
                raise
            
        except S3Error as e:
            if e.code == "NoSuchKey":
                logger.warning(f"File not found: {file_path}")
                return None
            else:
                logger.error(f"Failed to retrieve file: {e}")
                raise
    
    def _sync_stream_download(self, file_path: str, temp_file):
        """Synchronous streaming download for thread pool"""
        response = self.client.get_object(self.bucket_name, file_path)
        
        try:
            # Stream data in chunks
            while True:
                chunk = response.read(self.chunk_size)
                if not chunk:
                    break
                temp_file.write(chunk)
            
            temp_file.flush()
            
        finally:
            response.close()
            response.release_conn()
    
    async def delete_file(self, file_path: str) -> bool:
        """OPTIMIZED: Delete file with async wrapper"""
        try:
            loop = asyncio.get_event_loop()
            thread_pool = get_io_thread_pool()
            
            # Delete object using thread pool
            await loop.run_in_executor(
                thread_pool,
                self.client.remove_object,
                self.bucket_name,
                file_path
            )
            
            # Capture test event
            if self.test_hooks:
                await self.test_hooks.capture_event(
                    "storage", "file_deleted",
                    {"file_path": file_path}
                )
            
            logger.info(f"File deleted: {file_path}")
            return True
            
        except S3Error as e:
            if e.code == "NoSuchKey":
                logger.warning(f"File not found for deletion: {file_path}")
                return False
            else:
                logger.error(f"Failed to delete file: {e}")
                raise
        except Exception as e:
            logger.error(f"Unexpected error deleting file: {e}")
            raise
    
    async def file_exists(self, file_path: str) -> bool:
        """OPTIMIZED: Check if file exists with async wrapper"""
        try:
            loop = asyncio.get_event_loop()
            thread_pool = get_io_thread_pool()
            
            # Check object existence using thread pool
            await loop.run_in_executor(
                thread_pool,
                self.client.stat_object,
                self.bucket_name,
                file_path
            )
            return True
            
        except S3Error as e:
            if e.code == "NoSuchKey":
                return False
            else:
                logger.error(f"Failed to check file existence: {e}")
                raise
        except Exception as e:
            logger.error(f"Unexpected error checking file existence: {e}")
            raise
    
    async def get_file_info(self, file_path: str) -> Optional[FileInfoModel]:
        """OPTIMIZED: Get file information with async wrapper"""
        try:
            loop = asyncio.get_event_loop()
            thread_pool = get_io_thread_pool()
            
            # Get object metadata using thread pool
            stat = await loop.run_in_executor(
                thread_pool,
                self.client.stat_object,
                self.bucket_name,
                file_path
            )
            
            return FileInfoModel(
                path=file_path,
                size=stat.size,
                etag=stat.etag,
                last_modified=stat.last_modified,
                content_type=stat.content_type,
                metadata=stat.metadata or {}
            )
            
        except S3Error as e:
            if e.code == "NoSuchKey":
                return None
            else:
                logger.error(f"Failed to get file info: {e}")
                raise
        except Exception as e:
            logger.error(f"Unexpected error getting file info: {e}")
            raise
    
    async def generate_upload_url(
        self,
        document_id: str,
        filename: str,
        expires_minutes: int = 60
    ) -> str:
        """OPTIMIZED: Generate presigned URL for file upload with async wrapper"""
        try:
            from datetime import timedelta
            
            object_path = f"documents/{document_id}/{filename}"
            expires = timedelta(minutes=expires_minutes)
            
            loop = asyncio.get_event_loop()
            thread_pool = get_io_thread_pool()
            
            # Generate presigned URL using thread pool
            url = await loop.run_in_executor(
                thread_pool,
                self.client.presigned_put_object,
                self.bucket_name,
                object_path,
                expires
            )
            
            logger.info(f"Generated upload URL for document {document_id} (expires in {expires_minutes}m)")
            return url
            
        except Exception as e:
            logger.error(f"Failed to generate upload URL: {e}")
            raise
    
    async def generate_download_url(
        self,
        file_path: str,
        expires_minutes: int = 5
    ) -> str:
        """OPTIMIZED: Generate presigned URL for file download with async wrapper"""
        try:
            from datetime import timedelta
            
            expires = timedelta(minutes=expires_minutes)
            
            loop = asyncio.get_event_loop()
            thread_pool = get_io_thread_pool()
            
            # Generate presigned URL using thread pool
            url = await loop.run_in_executor(
                thread_pool,
                self.client.presigned_get_object,
                self.bucket_name,
                file_path,
                expires
            )
            
            logger.info(f"Generated download URL for {file_path} (expires in {expires_minutes}m)")
            return url
            
        except Exception as e:
            logger.error(f"Failed to generate download URL: {e}")
            raise
    
    async def copy_file(self, source_path: str, destination_path: str) -> bool:
        """OPTIMIZED: Copy file with async wrapper"""
        try:
            from minio.commonconfig import CopySource
            
            copy_source = CopySource(self.bucket_name, source_path)
            
            loop = asyncio.get_event_loop()
            thread_pool = get_io_thread_pool()
            
            # Copy object using thread pool
            await loop.run_in_executor(
                thread_pool,
                self.client.copy_object,
                self.bucket_name,
                destination_path,
                copy_source
            )
            
            logger.info(f"File copied from {source_path} to {destination_path}")
            return True
            
        except S3Error as e:
            if e.code == "NoSuchKey":
                logger.warning(f"Source file not found: {source_path}")
                return False
            else:
                logger.error(f"Failed to copy file: {e}")
                raise
        except Exception as e:
            logger.error(f"Unexpected error copying file: {e}")
            raise
    
    async def list_files(self, prefix: str = "", recursive: bool = False) -> List[Dict[str, Any]]:
        """OPTIMIZED: List files with async wrapper and streaming"""
        try:
            loop = asyncio.get_event_loop()
            thread_pool = get_io_thread_pool()
            
            # List objects using thread pool
            objects = await loop.run_in_executor(
                thread_pool,
                self._sync_list_objects,
                prefix,
                recursive
            )
            
            return objects
            
        except Exception as e:
            logger.error(f"Failed to list files: {e}")
            raise
    
    def _sync_list_objects(self, prefix: str, recursive: bool) -> List[Dict[str, Any]]:
        """Synchronous list objects for thread pool"""
        objects = []
        
        for obj in self.client.list_objects(
            bucket_name=self.bucket_name,
            prefix=prefix,
            recursive=recursive
        ):
            objects.append({
                "object_name": obj.object_name,
                "size": obj.size,
                "etag": obj.etag,
                "last_modified": obj.last_modified,
                "content_type": getattr(obj, 'content_type', None)
            })
        
        return objects
    
    async def get_storage_usage(self, prefix: str = "") -> Dict[str, Any]:
        """OPTIMIZED: Get storage usage statistics"""
        try:
            files = await self.list_files(prefix, recursive=True)
            total_size = sum(file["size"] for file in files)
            total_files = len(files)
            
            # Group by file types
            file_types = {}
            for file in files:
                name = file["object_name"]
                ext = name.split(".")[-1].lower() if "." in name else "no_extension"
                
                if ext not in file_types:
                    file_types[ext] = {"count": 0, "size": 0}
                
                file_types[ext]["count"] += 1
                file_types[ext]["size"] += file["size"]
            
            return {
                "total_files": total_files,
                "total_size": total_size,
                "total_size_mb": round(total_size / 1024 / 1024, 2),
                "by_file_type": file_types,
                "prefix": prefix,
                "calculated_at": datetime.now(timezone.utc).isoformat()
            }
            
        except Exception as e:
            logger.error(f"Failed to get storage usage: {e}")
            raise
    
    async def health_check(self) -> Dict[str, Any]:
        """OPTIMIZED: Perform storage service health check"""
        try:
            start_time = asyncio.get_event_loop().time()
            
            loop = asyncio.get_event_loop()
            thread_pool = get_io_thread_pool()
            
            # Check bucket existence using thread pool
            bucket_exists = await loop.run_in_executor(
                thread_pool,
                self.client.bucket_exists,
                self.bucket_name
            )
            
            response_time = asyncio.get_event_loop().time() - start_time
            
            return {
                "status": "healthy" if bucket_exists else "unhealthy",
                "bucket_name": self.bucket_name,
                "bucket_exists": bucket_exists,
                "endpoint": self.endpoint,
                "secure": self.secure,
                "response_time_ms": round(response_time * 1000, 2),
                "optimizations": {
                    "streaming_enabled": True,
                    "memory_limit_mb": self.memory_limit // 1024 // 1024,
                    "chunk_size_mb": self.chunk_size // 1024 // 1024,
                    "thread_pool_size": get_io_thread_pool()._max_workers
                }
            }
            
        except Exception as e:
            logger.error(f"Storage health check failed: {e}")
            return {
                "status": "unhealthy",
                "error": str(e),
                "error_type": type(e).__name__
            }
    
    async def cleanup_temp_files(self, max_age_hours: int = 24) -> Dict[str, int]:
        """OPTIMIZED: Clean up temporary files older than specified age"""
        try:
            cutoff_time = datetime.now(timezone.utc) - timedelta(hours=max_age_hours)
            
            # List temp files
            temp_files = await self.list_files(prefix="temp/", recursive=True)
            
            files_to_delete = []
            for file_info in temp_files:
                if file_info["last_modified"] < cutoff_time.replace(tzinfo=None):
                    files_to_delete.append(file_info["object_name"])
            
            # Delete files in parallel batches
            deleted_count = 0
            total_size_freed = 0
            
            # Process deletions in batches of 10
            batch_size = 10
            for i in range(0, len(files_to_delete), batch_size):
                batch = files_to_delete[i:i + batch_size]
                
                # Delete batch in parallel
                delete_tasks = []
                for file_path in batch:
                    # Find file size for stats
                    file_size = next((f["size"] for f in temp_files if f["object_name"] == file_path), 0)
                    
                    task = self._delete_file_with_size(file_path, file_size)
                    delete_tasks.append(task)
                
                results = await asyncio.gather(*delete_tasks, return_exceptions=True)
                
                for result in results:
                    if not isinstance(result, Exception):
                        deleted_count += 1
                        total_size_freed += result
            
            logger.info(f"Cleanup completed: {deleted_count} files deleted, {total_size_freed} bytes freed")
            
            return {
                "deleted_count": deleted_count,
                "size_freed": total_size_freed,
                "size_freed_mb": round(total_size_freed / 1024 / 1024, 2),
                "cutoff_time": cutoff_time.isoformat(),
                "total_temp_files": len(temp_files),
                "remaining_temp_files": len(temp_files) - deleted_count
            }
            
        except Exception as e:
            logger.error(f"Failed to cleanup temp files: {e}")
            raise
    
    async def _delete_file_with_size(self, file_path: str, file_size: int) -> int:
        """Helper function to delete file and return its size"""
        success = await self.delete_file(file_path)
        return file_size if success else 0
    
    def __del__(self):
        """Cleanup on destruction"""
        try:
            # Clean up thread pool if this is the last instance
            global _io_thread_pool
            if _io_thread_pool:
                _io_thread_pool.shutdown(wait=False)
                _io_thread_pool = None
        except Exception:
            pass  # Ignore errors during cleanup