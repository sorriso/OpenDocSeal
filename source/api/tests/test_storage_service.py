"""
Path: infrastructure/source/api/tests/test_storage_service.py
Version: 1 - StorageService Production Tests
"""

import pytest
import asyncio
import time
import tempfile
from datetime import datetime, timezone, timedelta
from unittest.mock import AsyncMock, MagicMock, patch, call
from typing import Dict, Any, List, Optional
from io import BytesIO
import minio
from minio.error import S3Error
import aiofiles

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from services.storage import StorageService
from models.base import FileInfoModel, ServiceHealthModel
from config import get_settings


class TestStorageServiceCreation:
    """Test StorageService creation and initialization"""
    
    def test_storage_service_initialization(self):
        """Test StorageService initialization"""
        
        with patch('minio.Minio') as mock_minio:
            mock_client = MagicMock()
            mock_minio.return_value = mock_client
            
            storage_service = StorageService()
            
            # Check MinIO client is created
            assert hasattr(storage_service, '_client')
            assert storage_service._client == mock_client
            
            # Check bucket name
            assert hasattr(storage_service, '_bucket_name')
            
            # Check memory limit for streaming
            assert hasattr(storage_service, 'memory_limit')
            assert storage_service.memory_limit == 50 * 1024 * 1024  # 50MB
            
            # Check metrics
            assert hasattr(storage_service, '_metrics')
            assert "files_stored" in storage_service._metrics
            assert "files_retrieved" in storage_service._metrics
            assert "total_bytes_stored" in storage_service._metrics
            
            # Verify MinIO client was initialized with correct parameters
            settings = get_settings()
            mock_minio.assert_called_once()
            call_args = mock_minio.call_args
            assert settings.minio_endpoint in str(call_args)


class TestBucketOperations:
    """Test bucket creation and management"""
    
    @pytest.fixture
    def storage_service(self):
        with patch('minio.Minio') as mock_minio:
            mock_client = MagicMock()
            mock_minio.return_value = mock_client
            return StorageService()
    
    @pytest.mark.asyncio
    async def test_ensure_bucket_exists_new_bucket(self, storage_service):
        """Test bucket creation when bucket doesn't exist"""
        
        # Mock bucket doesn't exist
        storage_service._client.bucket_exists.return_value = False
        storage_service._client.make_bucket.return_value = None
        
        await storage_service._ensure_bucket_exists()
        
        # Verify bucket existence check
        storage_service._client.bucket_exists.assert_called_once_with(
            storage_service._bucket_name
        )
        
        # Verify bucket creation
        storage_service._client.make_bucket.assert_called_once_with(
            storage_service._bucket_name
        )
    
    @pytest.mark.asyncio
    async def test_ensure_bucket_exists_existing_bucket(self, storage_service):
        """Test when bucket already exists"""
        
        # Mock bucket exists
        storage_service._client.bucket_exists.return_value = True
        
        await storage_service._ensure_bucket_exists()
        
        # Verify bucket existence check
        storage_service._client.bucket_exists.assert_called_once()
        
        # Verify bucket creation was NOT called
        storage_service._client.make_bucket.assert_not_called()
    
    @pytest.mark.asyncio
    async def test_ensure_bucket_creation_error(self, storage_service):
        """Test bucket creation error handling"""
        
        # Mock bucket doesn't exist
        storage_service._client.bucket_exists.return_value = False
        
        # Mock bucket creation error
        storage_service._client.make_bucket.side_effect = S3Error(
            "BucketAlreadyExists", "The bucket already exists", 
            "CreateBucket", "test-bucket"
        )
        
        # Should not raise exception
        await storage_service._ensure_bucket_exists()
        
        # Verify attempts were made
        storage_service._client.bucket_exists.assert_called_once()
        storage_service._client.make_bucket.assert_called_once()


class TestFileStorage:
    """Test file storage operations"""
    
    @pytest.fixture
    def storage_service(self):
        with patch('minio.Minio') as mock_minio:
            mock_client = MagicMock()
            mock_minio.return_value = mock_client
            service = StorageService()
            # Mock bucket exists
            service._client.bucket_exists.return_value = True
            return service
    
    @pytest.fixture
    def sample_file_data(self):
        return {
            "small": b"Hello, World!",  # 13 bytes
            "medium": b"A" * 1024,  # 1KB
            "large": b"B" * (10 * 1024 * 1024),  # 10MB
            "huge": b"C" * (100 * 1024 * 1024)  # 100MB
        }
    
    @pytest.mark.asyncio
    async def test_store_file_small_memory(self, storage_service, sample_file_data):
        """Test storing small file in memory"""
        
        file_data = sample_file_data["small"]
        file_path = "test/small_file.txt"
        content_type = "text/plain"
        
        # Mock successful upload
        storage_service._client.put_object.return_value = MagicMock(
            etag="abc123def456",
            version_id="version_1"
        )
        
        result = await storage_service.store_file(
            file_path, file_data, content_type
        )
        
        assert result is not None
        assert result.file_path == file_path
        assert result.size == len(file_data)
        assert result.content_type == content_type
        assert result.etag == "abc123def456"
        
        # Verify put_object was called with correct parameters
        storage_service._client.put_object.assert_called_once()
        call_args = storage_service._client.put_object.call_args
        assert call_args[0][0] == storage_service._bucket_name
        assert call_args[0][1] == file_path
        assert call_args[1]["content_type"] == content_type
        
        # Verify metrics are updated
        assert storage_service._metrics["files_stored"] == 1
        assert storage_service._metrics["total_bytes_stored"] == len(file_data)
    
    @pytest.mark.asyncio
    async def test_store_file_large_streaming(self, storage_service, sample_file_data):
        """Test storing large file with streaming"""
        
        file_data = sample_file_data["huge"]  # 100MB
        file_path = "test/large_file.bin"
        content_type = "application/octet-stream"
        
        # Mock successful streaming upload
        storage_service._client.put_object.return_value = MagicMock(
            etag="def456ghi789",
            version_id="version_2"
        )
        
        with patch('aiofiles.open', create=True) as mock_aiofiles:
            # Mock temporary file operations
            mock_file = AsyncMock()
            mock_file.write = AsyncMock()
            mock_file.flush = AsyncMock()
            mock_file.seek = AsyncMock()
            mock_file.name = "/tmp/temp_file_123"
            mock_aiofiles.return_value.__aenter__.return_value = mock_file
            
            with patch('tempfile.NamedTemporaryFile') as mock_temp:
                mock_temp.return_value.__enter__.return_value.name = "/tmp/temp_file_123"
                
                result = await storage_service.store_file(
                    file_path, file_data, content_type
                )
        
        assert result is not None
        assert result.file_path == file_path
        assert result.size == len(file_data)
        
        # Verify streaming strategy was used (large file)
        assert storage_service._metrics["files_stored"] == 1
        assert storage_service._metrics["total_bytes_stored"] == len(file_data)
    
    @pytest.mark.asyncio
    async def test_store_file_with_metadata(self, storage_service, sample_file_data):
        """Test storing file with metadata"""
        
        file_data = sample_file_data["medium"]
        file_path = "test/file_with_metadata.txt"
        content_type = "text/plain"
        metadata = {
            "user_id": "user_123",
            "document_type": "test_document",
            "version": "1.0"
        }
        
        storage_service._client.put_object.return_value = MagicMock(
            etag="metadata_test_123"
        )
        
        result = await storage_service.store_file(
            file_path, file_data, content_type, metadata=metadata
        )
        
        assert result is not None
        assert result.metadata == metadata
        
        # Verify metadata was passed to put_object
        call_args = storage_service._client.put_object.call_args
        assert "metadata" in call_args[1]
        assert call_args[1]["metadata"] == metadata
    
    @pytest.mark.asyncio
    async def test_store_file_upload_error(self, storage_service, sample_file_data):
        """Test handling of upload errors"""
        
        file_data = sample_file_data["small"]
        file_path = "test/error_file.txt"
        
        # Mock upload error
        storage_service._client.put_object.side_effect = S3Error(
            "NoSuchBucket", "The bucket does not exist", 
            "PutObject", "test-bucket"
        )
        
        result = await storage_service.store_file(
            file_path, file_data, "text/plain"
        )
        
        assert result is None
        
        # Verify error metrics are updated
        assert storage_service._metrics.get("upload_errors", 0) > 0


class TestFileRetrieval:
    """Test file retrieval operations"""
    
    @pytest.fixture
    def storage_service(self):
        with patch('minio.Minio') as mock_minio:
            mock_client = MagicMock()
            mock_minio.return_value = mock_client
            service = StorageService()
            service._client.bucket_exists.return_value = True
            return service
    
    @pytest.mark.asyncio
    async def test_get_file_success(self, storage_service):
        """Test successful file retrieval"""
        
        file_path = "test/retrieve_file.txt"
        file_content = b"Retrieved file content"
        
        # Mock MinIO response
        mock_response = MagicMock()
        mock_response.read.return_value = file_content
        mock_response.data = file_content
        storage_service._client.get_object.return_value = mock_response
        
        # Mock stat_object for file info
        mock_stat = MagicMock()
        mock_stat.size = len(file_content)
        mock_stat.content_type = "text/plain"
        mock_stat.etag = "retrieve_test_123"
        mock_stat.last_modified = datetime.now(timezone.utc)
        mock_stat.metadata = {"user_id": "user_123"}
        storage_service._client.stat_object.return_value = mock_stat
        
        result = await storage_service.get_file(file_path)
        
        assert result is not None
        assert result["content"] == file_content
        assert result["info"].size == len(file_content)
        assert result["info"].content_type == "text/plain"
        assert result["info"].metadata == {"user_id": "user_123"}
        
        # Verify correct calls were made
        storage_service._client.get_object.assert_called_once_with(
            storage_service._bucket_name, file_path
        )
        storage_service._client.stat_object.assert_called_once_with(
            storage_service._bucket_name, file_path
        )
        
        # Verify metrics
        assert storage_service._metrics["files_retrieved"] == 1
    
    @pytest.mark.asyncio
    async def test_get_file_not_found(self, storage_service):
        """Test file retrieval when file doesn't exist"""
        
        file_path = "test/nonexistent_file.txt"
        
        # Mock file not found error
        storage_service._client.get_object.side_effect = S3Error(
            "NoSuchKey", "The specified key does not exist",
            "GetObject", file_path
        )
        
        result = await storage_service.get_file(file_path)
        
        assert result is None
    
    @pytest.mark.asyncio
    async def test_get_file_info_only(self, storage_service):
        """Test getting file info without content"""
        
        file_path = "test/info_only_file.txt"
        
        # Mock stat_object
        mock_stat = MagicMock()
        mock_stat.size = 1024
        mock_stat.content_type = "application/pdf"
        mock_stat.etag = "info_only_test_123"
        mock_stat.last_modified = datetime.now(timezone.utc)
        mock_stat.metadata = {}
        storage_service._client.stat_object.return_value = mock_stat
        
        result = await storage_service.get_file_info(file_path)
        
        assert result is not None
        assert result.size == 1024
        assert result.content_type == "application/pdf"
        assert result.etag == "info_only_test_123"
        
        # Verify only stat_object was called, not get_object
        storage_service._client.stat_object.assert_called_once()
        storage_service._client.get_object.assert_not_called()


class TestPresignedURLs:
    """Test presigned URL operations"""
    
    @pytest.fixture
    def storage_service(self):
        with patch('minio.Minio') as mock_minio:
            mock_client = MagicMock()
            mock_minio.return_value = mock_client
            return StorageService()
    
    def test_generate_download_url(self, storage_service):
        """Test download URL generation"""
        
        file_path = "test/download_file.txt"
        expiry_minutes = 60
        
        expected_url = "https://minio.example.com/bucket/test/download_file.txt?signed=true"
        storage_service._client.presigned_get_object.return_value = expected_url
        
        result = storage_service.generate_download_url(file_path, expiry_minutes)
        
        assert result == expected_url
        
        # Verify correct call was made
        storage_service._client.presigned_get_object.assert_called_once_with(
            storage_service._bucket_name,
            file_path,
            expires=timedelta(minutes=expiry_minutes)
        )
    
    def test_generate_upload_url(self, storage_service):
        """Test upload URL generation"""
        
        file_path = "test/upload_file.txt"
        expiry_minutes = 30
        
        expected_url = "https://minio.example.com/bucket/test/upload_file.txt?upload=true"
        storage_service._client.presigned_put_object.return_value = expected_url
        
        result = storage_service.generate_upload_url(file_path, expiry_minutes)
        
        assert result == expected_url
        
        # Verify correct call was made
        storage_service._client.presigned_put_object.assert_called_once_with(
            storage_service._bucket_name,
            file_path,
            expires=timedelta(minutes=expiry_minutes)
        )
    
    def test_generate_url_error(self, storage_service):
        """Test URL generation error handling"""
        
        file_path = "test/error_file.txt"
        
        # Mock error
        storage_service._client.presigned_get_object.side_effect = S3Error(
            "InvalidRequest", "Invalid request", "PresignedGet", file_path
        )
        
        result = storage_service.generate_download_url(file_path)
        
        assert result is None


class TestFileOperations:
    """Test additional file operations"""
    
    @pytest.fixture
    def storage_service(self):
        with patch('minio.Minio') as mock_minio:
            mock_client = MagicMock()
            mock_minio.return_value = mock_client
            return StorageService()
    
    @pytest.mark.asyncio
    async def test_delete_file_success(self, storage_service):
        """Test successful file deletion"""
        
        file_path = "test/delete_file.txt"
        
        # Mock successful deletion
        storage_service._client.remove_object.return_value = None
        
        result = await storage_service.delete_file(file_path)
        
        assert result is True
        
        # Verify correct call was made
        storage_service._client.remove_object.assert_called_once_with(
            storage_service._bucket_name, file_path
        )
    
    @pytest.mark.asyncio
    async def test_delete_file_not_found(self, storage_service):
        """Test deleting non-existent file"""
        
        file_path = "test/nonexistent_delete.txt"
        
        # Mock file not found error
        storage_service._client.remove_object.side_effect = S3Error(
            "NoSuchKey", "The specified key does not exist",
            "DeleteObject", file_path
        )
        
        result = await storage_service.delete_file(file_path)
        
        assert result is False
    
    @pytest.mark.asyncio
    async def test_list_files_success(self, storage_service):
        """Test successful file listing"""
        
        prefix = "test/"
        
        # Mock MinIO list_objects response
        mock_objects = [
            MagicMock(object_name="test/file1.txt", size=100),
            MagicMock(object_name="test/file2.txt", size=200),
            MagicMock(object_name="test/subdir/file3.txt", size=300)
        ]
        storage_service._client.list_objects.return_value = mock_objects
        
        result = await storage_service.list_files(prefix)
        
        assert result is not None
        assert len(result) == 3
        assert result[0]["name"] == "test/file1.txt"
        assert result[0]["size"] == 100
        assert result[1]["name"] == "test/file2.txt"
        assert result[2]["name"] == "test/subdir/file3.txt"
        
        # Verify correct call was made
        storage_service._client.list_objects.assert_called_once_with(
            storage_service._bucket_name, prefix=prefix, recursive=True
        )
    
    @pytest.mark.asyncio
    async def test_list_files_empty(self, storage_service):
        """Test listing files with no results"""
        
        prefix = "empty/"
        
        # Mock empty response
        storage_service._client.list_objects.return_value = []
        
        result = await storage_service.list_files(prefix)
        
        assert result == []


class TestHealthCheck:
    """Test health check functionality"""
    
    @pytest.fixture
    def storage_service(self):
        with patch('minio.Minio') as mock_minio:
            mock_client = MagicMock()
            mock_minio.return_value = mock_client
            return StorageService()
    
    @pytest.mark.asyncio
    async def test_health_check_healthy(self, storage_service):
        """Test health check when storage is healthy"""
        
        # Mock successful bucket existence check
        storage_service._client.bucket_exists.return_value = True
        
        # Mock list operation
        storage_service._client.list_objects.return_value = []
        
        health = await storage_service.health_check()
        
        assert health["status"] == "healthy"
        assert "bucket_accessible" in health
        assert health["bucket_accessible"] is True
        assert "response_time" in health
    
    @pytest.mark.asyncio
    async def test_health_check_unhealthy(self, storage_service):
        """Test health check when storage is unhealthy"""
        
        # Mock connection error
        storage_service._client.bucket_exists.side_effect = Exception("Connection failed")
        
        health = await storage_service.health_check()
        
        assert health["status"] == "unhealthy"
        assert "error" in health
        assert "connection failed" in health["error"].lower()


class TestStorageStrategy:
    """Test storage strategy selection"""
    
    @pytest.fixture
    def storage_service(self):
        with patch('minio.Minio') as mock_minio:
            mock_client = MagicMock()
            mock_minio.return_value = mock_client
            service = StorageService()
            service._client.bucket_exists.return_value = True
            return service
    
    def test_storage_strategy_selection(self, storage_service):
        """Test storage strategy based on file size"""
        
        # Small file - should use memory strategy
        small_data = b"A" * 1024  # 1KB
        strategy = storage_service._select_storage_strategy(len(small_data))
        assert strategy == "memory"
        
        # Large file - should use streaming strategy
        large_data = b"B" * (100 * 1024 * 1024)  # 100MB
        strategy = storage_service._select_storage_strategy(len(large_data))
        assert strategy == "streaming"
        
        # Medium file (around threshold) - should use memory
        medium_data = b"C" * (40 * 1024 * 1024)  # 40MB (under 50MB threshold)
        strategy = storage_service._select_storage_strategy(len(medium_data))
        assert strategy == "memory"


class TestMetrics:
    """Test metrics collection and reporting"""
    
    @pytest.fixture
    def storage_service(self):
        with patch('minio.Minio') as mock_minio:
            mock_client = MagicMock()
            mock_minio.return_value = mock_client
            return StorageService()
    
    def test_metrics_initialization(self, storage_service):
        """Test metrics are properly initialized"""
        
        expected_metrics = [
            "files_stored", "files_retrieved", "files_deleted",
            "total_bytes_stored", "total_bytes_retrieved",
            "upload_errors", "download_errors"
        ]
        
        for metric in expected_metrics:
            assert metric in storage_service._metrics
            assert isinstance(storage_service._metrics[metric], (int, float))
    
    @pytest.mark.asyncio
    async def test_metrics_update_on_operations(self, storage_service):
        """Test metrics are updated during operations"""
        
        initial_stored = storage_service._metrics["files_stored"]
        initial_bytes = storage_service._metrics["total_bytes_stored"]
        
        file_data = b"Test file for metrics"
        file_path = "test/metrics_file.txt"
        
        # Mock successful upload
        storage_service._client.put_object.return_value = MagicMock(etag="metrics_test")
        
        await storage_service.store_file(file_path, file_data, "text/plain")
        
        # Verify metrics were updated
        assert storage_service._metrics["files_stored"] == initial_stored + 1
        assert storage_service._metrics["total_bytes_stored"] == initial_bytes + len(file_data)
    
    def test_get_metrics(self, storage_service):
        """Test metrics retrieval"""
        
        # Set some test metrics
        storage_service._metrics.update({
            "files_stored": 100,
            "files_retrieved": 150,
            "total_bytes_stored": 1024 * 1024 * 100,  # 100MB
            "upload_errors": 5,
            "download_errors": 2
        })
        
        metrics = storage_service.get_metrics()
        
        assert metrics["files_stored"] == 100
        assert metrics["files_retrieved"] == 150
        assert metrics["total_bytes_stored"] == 1024 * 1024 * 100
        assert metrics["upload_errors"] == 5
        assert metrics["download_errors"] == 2
        assert "success_rate" in metrics
        
        # Calculate expected success rate
        total_operations = 100 + 150  # stored + retrieved
        total_errors = 5 + 2  # upload + download errors
        expected_success_rate = ((total_operations - total_errors) / total_operations) * 100
        assert abs(metrics["success_rate"] - expected_success_rate) < 0.01


class TestErrorHandling:
    """Test comprehensive error handling"""
    
    @pytest.fixture
    def storage_service(self):
        with patch('minio.Minio') as mock_minio:
            mock_client = MagicMock()
            mock_minio.return_value = mock_client
            return StorageService()
    
    @pytest.mark.asyncio
    async def test_connection_timeout_handling(self, storage_service):
        """Test handling of connection timeouts"""
        
        file_path = "test/timeout_file.txt"
        file_data = b"Timeout test data"
        
        # Mock timeout error
        storage_service._client.put_object.side_effect = Exception("Connection timeout")
        
        result = await storage_service.store_file(file_path, file_data, "text/plain")
        
        assert result is None
        
        # Verify error metrics are updated
        assert storage_service._metrics.get("upload_errors", 0) > 0
    
    @pytest.mark.asyncio
    async def test_disk_space_error_handling(self, storage_service):
        """Test handling of insufficient disk space"""
        
        file_path = "test/diskspace_file.txt"
        file_data = b"Disk space test"
        
        # Mock disk space error
        storage_service._client.put_object.side_effect = S3Error(
            "InternalError", "Insufficient storage space",
            "PutObject", file_path
        )
        
        result = await storage_service.store_file(file_path, file_data, "text/plain")
        
        assert result is None
    
    @pytest.mark.asyncio
    async def test_concurrent_access_safety(self, storage_service):
        """Test thread safety for concurrent operations"""
        
        # Mock successful operations
        storage_service._client.put_object.return_value = MagicMock(etag="concurrent_test")
        
        # Create multiple concurrent store operations
        tasks = []
        for i in range(10):
            task = asyncio.create_task(
                storage_service.store_file(
                    f"test/concurrent_{i}.txt",
                    f"Data for file {i}".encode(),
                    "text/plain"
                )
            )
            tasks.append(task)
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # All operations should complete successfully
        successful_results = [r for r in results if not isinstance(r, Exception)]
        assert len(successful_results) == 10
        
        # Metrics should be consistent
        assert storage_service._metrics["files_stored"] == 10


if __name__ == "__main__":
    # Run tests with pytest
    pytest.main([__file__, "-v", "--tb=short"])