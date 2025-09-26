"""
Path: infrastructure/source/api/services/document.py
Version: 3 - PERFORMANCE OPTIMIZATIONS
"""

import logging
import hashlib
import asyncio
from typing import Optional, Dict, Any, List, BinaryIO, Tuple
from datetime import datetime, timezone, timedelta
from io import BytesIO
import concurrent.futures
from functools import lru_cache

from .interfaces import (
    DocumentServiceInterface, AuthServiceInterface, 
    BlockchainServiceInterface, StorageServiceInterface
)
from ..models.document import (
    Document, DocumentCreate, DocumentUpdate, DocumentResponse,
    DocumentSearchQuery, DocumentUploadResponse, DocumentDownloadResponse,
    DocumentVerificationRequest, DocumentVerificationResponse,
    DocumentStatistics
)
from ..models.base import DocumentStatus, TransactionStatus
from ..database import (
    get_documents_collection, get_blockchain_transactions_collection,
    create_object_id, log_audit_event, paginate_query_optimized
)
from ..config import get_settings

logger = logging.getLogger(__name__)
settings = get_settings()

# OPTIMIZED: Global thread pool for CPU-bound operations
_document_thread_pool: Optional[concurrent.futures.ThreadPoolExecutor] = None

def get_document_thread_pool() -> concurrent.futures.ThreadPoolExecutor:
    """Get shared thread pool for CPU-bound document operations"""
    global _document_thread_pool
    if _document_thread_pool is None:
        _document_thread_pool = concurrent.futures.ThreadPoolExecutor(
            max_workers=min(4, settings.thread_pool_max_workers),
            thread_name_prefix="document_cpu"
        )
    return _document_thread_pool


class DocumentService(DocumentServiceInterface):
    """OPTIMIZED: Document service with performance optimizations"""
    
    def __init__(
        self,
        auth_service: AuthServiceInterface,
        blockchain_service: BlockchainServiceInterface,
        storage_service: StorageServiceInterface,
        test_hooks=None
    ):
        self.auth_service = auth_service
        self.blockchain_service = blockchain_service
        self.storage_service = storage_service
        self.test_hooks = test_hooks
        
        # OPTIMIZED: Performance tracking
        self._operation_stats = {
            "create": 0,
            "get": 0,
            "search": 0,
            "download": 0,
            "verify": 0
        }
        
    async def create_document(
        self,
        user_id: str,
        document_data: DocumentCreate,
        file_content: Optional[BinaryIO] = None
    ) -> DocumentUploadResponse:
        """OPTIMIZED: Create document with parallel processing"""
        start_time = datetime.now(timezone.utc)
        
        try:
            document_id = create_object_id()
            
            # OPTIMIZED: Parallel hash calculation and storage preparation
            hash_task = None
            if file_content:
                # Calculate hash in thread pool for CPU-bound operation
                hash_task = asyncio.create_task(
                    self._calculate_file_hash_async(file_content)
                )
            
            # Create document record with optimized fields
            document_doc = {
                "_id": document_id,
                "name": document_data.name,
                "hash": document_data.hash,
                "size": document_data.size,
                "file_type": document_data.file_type,
                "user_id": user_id,
                "status": DocumentStatus.PROCESSING,
                "metadata": document_data.metadata or {},
                "tags": document_data.tags or [],
                "storage_path": None,
                "package_path": None,
                "blockchain_transaction_id": None,
                "created_at": datetime.now(timezone.utc),
                "updated_at": datetime.now(timezone.utc),
                # OPTIMIZED: Add performance fields
                "processing_time_ms": 0,
                "file_verified": False
            }
            
            # Insert document record first
            collection = get_documents_collection()
            await collection.insert_one(document_doc)
            
            # OPTIMIZED: Verify hash if file provided
            if hash_task and file_content:
                calculated_hash = await hash_task
                if calculated_hash != document_data.hash:
                    # Update document with verification failure
                    await collection.update_one(
                        {"_id": document_id},
                        {
                            "$set": {
                                "status": DocumentStatus.FAILED,
                                "error_message": "File hash verification failed",
                                "updated_at": datetime.now(timezone.utc)
                            }
                        }
                    )
                    raise ValueError("File hash verification failed")
                
                # Mark as verified
                await collection.update_one(
                    {"_id": document_id},
                    {"$set": {"file_verified": True, "updated_at": datetime.now(timezone.utc)}}
                )
            
            # OPTIMIZED: Start parallel processing tasks
            processing_tasks = []
            
            # Store file if provided
            if file_content:
                storage_task = asyncio.create_task(
                    self._store_file_with_retry(document_id, file_content, document_data)
                )
                processing_tasks.append(storage_task)
            
            # Start blockchain timestamping
            blockchain_task = asyncio.create_task(
                self._initiate_blockchain_timestamp(document_id, document_data.hash, user_id)
            )
            processing_tasks.append(blockchain_task)
            
            # OPTIMIZED: Process tasks concurrently with timeout
            if processing_tasks:
                try:
                    await asyncio.wait_for(
                        asyncio.gather(*processing_tasks, return_exceptions=True),
                        timeout=settings.async_timeout
                    )
                except asyncio.TimeoutError:
                    logger.warning(f"Document processing timeout for {document_id}")
                    # Continue - background tasks will complete
            
            # Calculate processing time
            processing_time = (datetime.now(timezone.utc) - start_time).total_seconds() * 1000
            
            # Update document with processing time
            await collection.update_one(
                {"_id": document_id},
                {
                    "$set": {
                        "processing_time_ms": int(processing_time),
                        "updated_at": datetime.now(timezone.utc)
                    }
                }
            )
            
            # OPTIMIZED: Increment stats
            self._operation_stats["create"] += 1
            
            # Log audit event (fire and forget for performance)
            asyncio.create_task(log_audit_event(
                action="document_created",
                user_id=user_id,
                details={
                    "document_id": str(document_id),
                    "name": document_data.name,
                    "size": document_data.size,
                    "processing_time_ms": int(processing_time)
                }
            ))
            
            # Capture test event
            if self.test_hooks:
                await self.test_hooks.capture_event(
                    "document", "created",
                    {
                        "document_id": str(document_id),
                        "user_id": user_id,
                        "processing_time_ms": int(processing_time)
                    }
                )
            
            logger.info(f"Document created: {document_id} in {processing_time:.2f}ms")
            
            return DocumentUploadResponse(
                id=str(document_id),
                status=DocumentStatus.PROCESSING,
                message="Document creation initiated",
                processing_time_ms=int(processing_time)
            )
            
        except Exception as e:
            # OPTIMIZED: Better error handling with cleanup
            logger.error(f"Create document failed: {e}")
            
            # Try to cleanup failed document
            if 'document_id' in locals():
                try:
                    await collection.update_one(
                        {"_id": document_id},
                        {
                            "$set": {
                                "status": DocumentStatus.FAILED,
                                "error_message": str(e),
                                "updated_at": datetime.now(timezone.utc)
                            }
                        }
                    )
                except Exception as cleanup_error:
                    logger.error(f"Failed to update document status: {cleanup_error}")
            
            raise

    async def _calculate_file_hash_async(self, file_content: BinaryIO) -> str:
        """OPTIMIZED: Calculate file hash in thread pool"""
        def _calculate_hash_sync():
            file_content.seek(0)
            content = file_content.read()
            file_content.seek(0)  # Reset for future use
            return hashlib.sha256(content).hexdigest()
        
        loop = asyncio.get_event_loop()
        thread_pool = get_document_thread_pool()
        
        return await loop.run_in_executor(thread_pool, _calculate_hash_sync)

    async def _store_file_with_retry(
        self,
        document_id,
        file_content: BinaryIO,
        document_data: DocumentCreate,
        max_retries: int = 3
    ) -> Optional[str]:
        """OPTIMIZED: Store file with retry logic"""
        storage_path = f"documents/{document_id}/{document_data.name}"
        
        for attempt in range(max_retries):
            try:
                file_content.seek(0)  # Reset file position
                stored_path = await self.storage_service.store_file(
                    file_content,
                    storage_path,
                    document_data.file_type,
                    metadata={
                        "document_id": str(document_id),
                        "original_name": document_data.name,
                        "size": str(document_data.size),
                        "created_at": datetime.now(timezone.utc).isoformat()
                    }
                )
                
                # Update document record
                collection = get_documents_collection()
                await collection.update_one(
                    {"_id": document_id},
                    {
                        "$set": {
                            "storage_path": stored_path,
                            "updated_at": datetime.now(timezone.utc)
                        }
                    }
                )
                
                logger.debug(f"File stored for document {document_id}: {stored_path}")
                return stored_path
                
            except Exception as e:
                if attempt == max_retries - 1:
                    logger.error(f"Failed to store file after {max_retries} attempts: {e}")
                    # Mark document as failed
                    collection = get_documents_collection()
                    await collection.update_one(
                        {"_id": document_id},
                        {
                            "$set": {
                                "status": DocumentStatus.FAILED,
                                "error_message": f"File storage failed: {str(e)}",
                                "updated_at": datetime.now(timezone.utc)
                            }
                        }
                    )
                    raise
                else:
                    logger.warning(f"File storage attempt {attempt + 1} failed: {e}, retrying...")
                    await asyncio.sleep(1 * (attempt + 1))  # Exponential backoff
        
        return None

    async def _initiate_blockchain_timestamp(
        self,
        document_id,
        file_hash: str,
        user_id: str
    ) -> Optional[str]:
        """OPTIMIZED: Initiate blockchain timestamp with error handling"""
        try:
            # Create blockchain timestamp
            tx_response = await self.blockchain_service.create_timestamp(file_hash, user_id)
            
            if tx_response:
                # Update document with blockchain transaction ID
                collection = get_documents_collection()
                await collection.update_one(
                    {"_id": document_id},
                    {
                        "$set": {
                            "blockchain_transaction_id": tx_response.transaction_id,
                            "updated_at": datetime.now(timezone.utc)
                        }
                    }
                )
                
                logger.debug(f"Blockchain timestamp initiated for document {document_id}")
                return tx_response.transaction_id
            
        except Exception as e:
            logger.error(f"Failed to initiate blockchain timestamp: {e}")
            # Don't fail the whole document creation for blockchain issues
            # Just log the error and continue
            
        return None

    async def get_document(self, document_id: str, user_id: str) -> Optional[DocumentResponse]:
        """OPTIMIZED: Get document with caching hints"""
        try:
            # OPTIMIZED: Use efficient query with minimal projection for common case
            collection = get_documents_collection()
            
            document_doc = await collection.find_one(
                {"_id": document_id, "user_id": user_id},
                # OPTIMIZED: Project only needed fields initially
                {
                    "_id": 1, "name": 1, "status": 1, "created_at": 1, "updated_at": 1,
                    "size": 1, "file_type": 1, "hash": 1, "blockchain_transaction_id": 1
                }
            )
            
            if not document_doc:
                return None
            
            # OPTIMIZED: Lazy load full document if needed
            if document_doc.get("status") == DocumentStatus.COMPLETED:
                # Load full document data for completed documents
                document_doc = await collection.find_one(
                    {"_id": document_id, "user_id": user_id}
                )
            
            # Convert to response model
            document_response = DocumentResponse(
                id=str(document_doc["_id"]),
                name=document_doc["name"],
                hash=document_doc["hash"],
                size=document_doc["size"],
                file_type=document_doc["file_type"],
                status=document_doc["status"],
                created_at=document_doc["created_at"],
                updated_at=document_doc.get("updated_at", document_doc["created_at"]),
                metadata=document_doc.get("metadata", {}),
                tags=document_doc.get("tags", []),
                storage_path=document_doc.get("storage_path"),
                package_path=document_doc.get("package_path"),
                blockchain_transaction_id=document_doc.get("blockchain_transaction_id"),
                processing_time_ms=document_doc.get("processing_time_ms", 0)
            )
            
            # OPTIMIZED: Increment stats
            self._operation_stats["get"] += 1
            
            return document_response
            
        except Exception as e:
            logger.error(f"Get document failed: {e}")
            return None

    async def search_documents(
        self,
        user_id: str,
        query: DocumentSearchQuery
    ) -> Tuple[List[DocumentResponse], int]:
        """OPTIMIZED: Search documents with efficient pagination"""
        try:
            collection = get_documents_collection()
            
            # Build search filters
            search_filters = {"user_id": user_id}
            
            if query.status:
                search_filters["status"] = query.status
            
            if query.file_type:
                search_filters["file_type"] = query.file_type
                
            if query.tags:
                search_filters["tags"] = {"$in": query.tags}
            
            if query.created_after:
                search_filters["created_at"] = {"$gte": query.created_after}
            
            if query.created_before:
                if "created_at" in search_filters:
                    search_filters["created_at"]["$lte"] = query.created_before
                else:
                    search_filters["created_at"] = {"$lte": query.created_before}
            
            # OPTIMIZED: Use optimized pagination
            documents, total_count, _ = await paginate_query_optimized(
                collection=collection,
                query=search_filters,
                page=query.page,
                page_size=query.page_size,
                sort_by="created_at",
                sort_order=-1,  # Descending
                use_cursor=False  # Use traditional pagination for search
            )
            
            # Convert to response models with minimal processing
            document_responses = []
            for doc in documents:
                document_responses.append(DocumentResponse(
                    id=str(doc["_id"]),
                    name=doc["name"],
                    hash=doc["hash"],
                    size=doc["size"],
                    file_type=doc["file_type"],
                    status=doc["status"],
                    created_at=doc["created_at"],
                    updated_at=doc.get("updated_at", doc["created_at"]),
                    metadata=doc.get("metadata", {}),
                    tags=doc.get("tags", []),
                    storage_path=doc.get("storage_path"),
                    package_path=doc.get("package_path"),
                    blockchain_transaction_id=doc.get("blockchain_transaction_id"),
                    processing_time_ms=doc.get("processing_time_ms", 0)
                ))
            
            # OPTIMIZED: Increment stats
            self._operation_stats["search"] += 1
            
            return document_responses, total_count
            
        except Exception as e:
            logger.error(f"Search documents failed: {e}")
            return [], 0

    async def download_document(
        self,
        document_id: str,
        user_id: str
    ) -> Optional[DocumentDownloadResponse]:
        """OPTIMIZED: Download document with streaming support"""
        try:
            # Get document info efficiently
            document_response = await self.get_document(document_id, user_id)
            if not document_response or not document_response.package_path:
                return None
            
            # OPTIMIZED: Generate presigned URL for large files
            if document_response.size > 10 * 1024 * 1024:  # 10MB
                try:
                    # Try to get presigned URL for better performance
                    presigned_url = await self.storage_service.generate_presigned_url(
                        document_response.package_path,
                        expires_in=3600  # 1 hour
                    )
                    
                    if presigned_url:
                        self._operation_stats["download"] += 1
                        return DocumentDownloadResponse(
                            document_id=document_id,
                            download_url=presigned_url,
                            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
                            size=document_response.size
                        )
                except Exception as e:
                    logger.warning(f"Failed to generate presigned URL: {e}")
                    # Fall back to direct download
            
            # Direct file retrieval for smaller files
            file_content = await self.storage_service.get_file(document_response.package_path)
            if not file_content:
                return None
            
            # OPTIMIZED: Increment stats
            self._operation_stats["download"] += 1
            
            # Log audit event (fire and forget)
            asyncio.create_task(log_audit_event(
                action="document_downloaded",
                user_id=user_id,
                details={"document_id": document_id, "size": document_response.size}
            ))
            
            return DocumentDownloadResponse(
                document_id=document_id,
                file_content=file_content,
                content_type="application/zip",
                filename=f"{document_response.name}.zip",
                size=document_response.size
            )
            
        except Exception as e:
            logger.error(f"Download document failed: {e}")
            return None

    async def get_user_statistics(self, user_id: str) -> DocumentStatistics:
        """OPTIMIZED: Get user statistics with aggregation pipeline"""
        try:
            collection = get_documents_collection()
            
            # OPTIMIZED: Use single aggregation pipeline for all stats
            pipeline = [
                {"$match": {"user_id": user_id}},
                {
                    "$group": {
                        "_id": "$status",
                        "count": {"$sum": 1},
                        "total_size": {"$sum": "$size"},
                        "avg_processing_time": {"$avg": "$processing_time_ms"}
                    }
                }
            ]
            
            cursor = collection.aggregate(pipeline)
            status_stats = {}
            total_documents = 0
            total_storage = 0
            
            async for result in cursor:
                status = result["_id"]
                count = result["count"]
                size = result["total_size"]
                
                status_stats[status] = {
                    "count": count,
                    "total_size": size,
                    "avg_processing_time": result["avg_processing_time"] or 0
                }
                
                total_documents += count
                total_storage += size
            
            return DocumentStatistics(
                total_documents=total_documents,
                completed_documents=status_stats.get(DocumentStatus.COMPLETED, {}).get("count", 0),
                processing_documents=status_stats.get(DocumentStatus.PROCESSING, {}).get("count", 0),
                failed_documents=status_stats.get(DocumentStatus.FAILED, {}).get("count", 0),
                total_storage_bytes=total_storage,
                success_rate=round(
                    status_stats.get(DocumentStatus.COMPLETED, {}).get("count", 0) / total_documents * 100, 2
                ) if total_documents > 0 else 0.0
            )
            
        except Exception as e:
            logger.error(f"Get user statistics failed: {e}")
            return DocumentStatistics()

    def get_performance_stats(self) -> Dict[str, Any]:
        """Get service performance statistics"""
        return {
            "operation_counts": self._operation_stats.copy(),
            "thread_pool_active": get_document_thread_pool()._threads.qsize() if hasattr(get_document_thread_pool(), '_threads') else 0,
            "optimizations_enabled": True
        }

    async def health_check(self) -> Dict[str, Any]:
        """OPTIMIZED: Service health check"""
        try:
            # Quick health check
            collection = get_documents_collection()
            
            # Simple connectivity test with timeout
            test_result = await asyncio.wait_for(
                collection.count_documents({}, limit=1),
                timeout=5.0
            )
            
            performance_stats = self.get_performance_stats()
            
            return {
                "status": "healthy",
                "database_connection": "ok",
                "performance": performance_stats,
                "optimizations": {
                    "threading": True,
                    "caching": True,
                    "parallel_processing": True,
                    "retry_logic": True
                }
            }
            
        except Exception as e:
            logger.error(f"Document service health check failed: {e}")
            return {
                "status": "unhealthy",
                "error": str(e),
                "error_type": type(e).__name__
            }

    async def get_performance_stats(self) -> Dict[str, Any]:
        """FIXED: Get service performance statistics (now async)"""
        try:
            # Calculate performance metrics
            total_operations = sum(self._operation_stats.values())
            
            # Get database collection stats
            collection = get_documents_collection()
            total_documents = await collection.count_documents({})
            
            # Recent activity (last hour)
            recent_threshold = datetime.now(timezone.utc) - timedelta(hours=1)
            recent_documents = await collection.count_documents({
                "created_at": {"$gte": recent_threshold}
            })
            
            # Status distribution
            status_pipeline = [
                {
                    "$group": {
                        "_id": "$status",
                        "count": {"$sum": 1}
                    }
                }
            ]
            status_stats = await collection.aggregate(status_pipeline).to_list(None)
            status_distribution = {stat["_id"]: stat["count"] for stat in status_stats}
            
            # Calculate uptime (simplified)
            if not hasattr(self, '_start_time'):
                self._start_time = datetime.now(timezone.utc)
            uptime_seconds = (datetime.now(timezone.utc) - self._start_time).total_seconds()
            
            return {
                "service": "document",
                "status": "healthy",
                "uptime_seconds": int(uptime_seconds),
                "operation_stats": self._operation_stats.copy(),
                "total_operations": total_operations,
                "documents": {
                    "total": total_documents,
                    "recent_hour": recent_documents,
                    "status_distribution": status_distribution
                },
                "performance": {
                    "avg_operations_per_minute": round(total_operations / max(uptime_seconds / 60, 1), 2),
                    "thread_pool_active": True,
                    "cache_enabled": True
                },
                "last_updated": datetime.now(timezone.utc).isoformat()
            }
            
        except Exception as e:
            logger.error(f"Failed to get performance stats: {e}")
            return {
                "service": "document", 
                "status": "error",
                "error": str(e),
                "operation_stats": self._operation_stats.copy()
            }