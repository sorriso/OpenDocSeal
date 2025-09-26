"""
Path: infrastructure/source/api/tests/test_document_service.py
Version: 2 - DocumentService Enhanced Coverage Tests
"""

import pytest
import asyncio
import time
from datetime import datetime, timezone, timedelta
from unittest.mock import AsyncMock, MagicMock, patch, call
from typing import Dict, Any, List
from io import BytesIO
import hashlib
import json

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from services.document import DocumentService
from services.interfaces import (
    AuthServiceInterface, BlockchainServiceInterface, StorageServiceInterface,
    NotificationServiceInterface, AuditServiceInterface
)
from models.document import (
    DocumentCreate, DocumentResponse, DocumentUploadResponse, DocumentSearchQuery,
    DocumentDownloadResponse, DocumentStatistics, ProofPackageInfo
)
from models.base import DocumentStatus, TransactionStatus
from models.blockchain import BlockchainTransaction, ProofVerificationResult


class TestDocumentServiceCreation:
    """Test DocumentService creation and initialization"""
    
    def test_document_service_initialization(self):
        """Test DocumentService initialization with dependencies"""
        
        auth_service = MagicMock(spec=AuthServiceInterface)
        blockchain_service = MagicMock(spec=BlockchainServiceInterface)
        storage_service = MagicMock(spec=StorageServiceInterface)
        
        doc_service = DocumentService(
            auth_service=auth_service,
            blockchain_service=blockchain_service,
            storage_service=storage_service
        )
        
        assert doc_service.auth_service == auth_service
        assert doc_service.blockchain_service == blockchain_service
        assert doc_service.storage_service == storage_service
        assert hasattr(doc_service, '_operation_stats')
        assert doc_service._operation_stats["create"] == 0
        assert doc_service._operation_stats["get"] == 0
        assert hasattr(doc_service, '_thread_pool')
        assert hasattr(doc_service, '_metrics')
    
    def test_document_service_with_optional_services(self):
        """Test DocumentService with optional notification and audit services"""
        
        auth_service = MagicMock(spec=AuthServiceInterface)
        blockchain_service = MagicMock(spec=BlockchainServiceInterface)
        storage_service = MagicMock(spec=StorageServiceInterface)
        notification_service = MagicMock(spec=NotificationServiceInterface)
        audit_service = MagicMock(spec=AuditServiceInterface)
        
        doc_service = DocumentService(
            auth_service=auth_service,
            blockchain_service=blockchain_service,
            storage_service=storage_service,
            notification_service=notification_service,
            audit_service=audit_service
        )
        
        assert doc_service.notification_service == notification_service
        assert doc_service.audit_service == audit_service


class TestDocumentCreation:
    """Test document creation with parallel processing optimizations"""
    
    @pytest.fixture
    def mock_services(self):
        """Mock all service dependencies"""
        auth_service = AsyncMock(spec=AuthServiceInterface)
        blockchain_service = AsyncMock(spec=BlockchainServiceInterface)
        storage_service = AsyncMock(spec=StorageServiceInterface)
        notification_service = AsyncMock(spec=NotificationServiceInterface)
        audit_service = AsyncMock(spec=AuditServiceInterface)
        
        return {
            "auth": auth_service,
            "blockchain": blockchain_service,
            "storage": storage_service,
            "notification": notification_service,
            "audit": audit_service
        }
    
    @pytest.fixture
    def document_service(self, mock_services):
        """Create DocumentService with mocked dependencies"""
        return DocumentService(
            auth_service=mock_services["auth"],
            blockchain_service=mock_services["blockchain"],
            storage_service=mock_services["storage"],
            notification_service=mock_services["notification"],
            audit_service=mock_services["audit"]
        )
    
    @pytest.fixture
    def sample_file_data(self):
        return {
            "small": b"Hello, World! This is a test document.",
            "medium": b"A" * 1024,  # 1KB
            "large": b"B" * (10 * 1024 * 1024),  # 10MB
        }
    
    @pytest.mark.asyncio
    async def test_create_document_complete_workflow(self, document_service, mock_services, sample_file_data):
        """Test complete document creation workflow with all services"""
        
        user_id = "user_123"
        file_data = sample_file_data["medium"]
        
        # Mock successful operations
        mock_services["storage"].store_file.return_value = MagicMock(
            file_path="docs/user_123/test_document.pdf",
            size=len(file_data),
            etag="etag123"
        )
        
        mock_services["blockchain"].create_timestamp.return_value = BlockchainTransaction(
            transaction_id="tx_123",
            document_hash=hashlib.sha256(file_data).hexdigest(),
            status=TransactionStatus.PENDING,
            blockchain_network="bitcoin",
            proof_type="opentimestamps"
        )
        
        mock_services["notification"].send_document_notification.return_value = True
        mock_services["audit"].log_audit_event.return_value = True
        
        with patch('services.document.get_documents_collection') as mock_collection:
            mock_db = AsyncMock()
            mock_collection.return_value = mock_db
            mock_db.insert_one.return_value = MagicMock(inserted_id="doc_123")
            
            # Mock document retrieval after creation
            mock_doc = {
                "_id": "doc_123",
                "user_id": user_id,
                "name": "test_document.pdf",
                "hash": hashlib.sha256(file_data).hexdigest(),
                "size": len(file_data),
                "file_type": "application/pdf",
                "status": DocumentStatus.PROCESSING,
                "created_at": datetime.now(timezone.utc),
                "updated_at": datetime.now(timezone.utc),
                "storage_path": "docs/user_123/test_document.pdf",
                "blockchain_transaction_id": "tx_123"
            }
            mock_db.find_one.return_value = mock_doc
            
            result = await document_service.create_document(
                user_id=user_id,
                filename="test_document.pdf",
                file_content=file_data,
                content_type="application/pdf",
                metadata={"author": "Test Author"}
            )
            
            assert result is not None
            assert result.id == "doc_123"
            assert result.status == DocumentStatus.PROCESSING
            assert result.blockchain_transaction_id == "tx_123"
            
            # Verify all services were called
            mock_services["storage"].store_file.assert_called_once()
            mock_services["blockchain"].create_timestamp.assert_called_once()
            mock_services["notification"].send_document_notification.assert_called_once()
            mock_services["audit"].log_audit_event.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_create_document_parallel_processing(self, document_service, mock_services, sample_file_data):
        """Test parallel processing optimization in document creation"""
        
        user_id = "user_123"
        file_data = sample_file_data["large"]  # Large file to trigger parallel processing
        
        # Mock services with delays to test parallel execution
        async def delayed_storage(*args, **kwargs):
            await asyncio.sleep(0.1)
            return MagicMock(file_path="docs/test.pdf", size=len(file_data), etag="etag123")
        
        async def delayed_blockchain(*args, **kwargs):
            await asyncio.sleep(0.1)
            return BlockchainTransaction(
                transaction_id="tx_123",
                document_hash=hashlib.sha256(file_data).hexdigest(),
                status=TransactionStatus.PENDING,
                blockchain_network="bitcoin",
                proof_type="opentimestamps"
            )
        
        mock_services["storage"].store_file.side_effect = delayed_storage
        mock_services["blockchain"].create_timestamp.side_effect = delayed_blockchain
        mock_services["notification"].send_document_notification.return_value = True
        mock_services["audit"].log_audit_event.return_value = True
        
        with patch('services.document.get_documents_collection') as mock_collection:
            mock_db = AsyncMock()
            mock_collection.return_value = mock_db
            mock_db.insert_one.return_value = MagicMock(inserted_id="doc_123")
            mock_db.find_one.return_value = {
                "_id": "doc_123",
                "user_id": user_id,
                "name": "large_test.pdf",
                "status": DocumentStatus.PROCESSING,
                "created_at": datetime.now(timezone.utc)
            }
            
            start_time = time.time()
            
            result = await document_service.create_document(
                user_id=user_id,
                filename="large_test.pdf",
                file_content=file_data,
                content_type="application/pdf"
            )
            
            execution_time = time.time() - start_time
            
            # Parallel execution should be faster than sequential (< 0.15s vs > 0.2s)
            assert execution_time < 0.15
            assert result is not None
    
    @pytest.mark.asyncio
    async def test_create_document_storage_failure_rollback(self, document_service, mock_services):
        """Test rollback when storage fails during document creation"""
        
        # Mock storage failure
        mock_services["storage"].store_file.side_effect = Exception("Storage failed")
        mock_services["blockchain"].create_timestamp.return_value = BlockchainTransaction(
            transaction_id="tx_123",
            document_hash="hash123",
            status=TransactionStatus.PENDING,
            blockchain_network="bitcoin",
            proof_type="opentimestamps"
        )
        
        result = await document_service.create_document(
            user_id="user_123",
            filename="test.pdf",
            file_content=b"test content",
            content_type="application/pdf"
        )
        
        assert result is None
        
        # Blockchain service should not be called if storage fails
        mock_services["blockchain"].create_timestamp.assert_not_called()
    
    @pytest.mark.asyncio
    async def test_create_document_blockchain_failure_handling(self, document_service, mock_services):
        """Test handling of blockchain service failure"""
        
        # Mock successful storage but failed blockchain
        mock_services["storage"].store_file.return_value = MagicMock(
            file_path="docs/test.pdf", size=100, etag="etag123"
        )
        mock_services["blockchain"].create_timestamp.side_effect = Exception("Blockchain unavailable")
        mock_services["audit"].log_audit_event.return_value = True
        
        with patch('services.document.get_documents_collection') as mock_collection:
            mock_db = AsyncMock()
            mock_collection.return_value = mock_db
            mock_db.insert_one.return_value = MagicMock(inserted_id="doc_123")
            mock_db.find_one.return_value = {
                "_id": "doc_123",
                "user_id": "user_123",
                "name": "test.pdf",
                "status": DocumentStatus.PENDING_BLOCKCHAIN,  # Special status for blockchain failure
                "created_at": datetime.now(timezone.utc)
            }
            
            result = await document_service.create_document(
                user_id="user_123",
                filename="test.pdf",
                file_content=b"test content",
                content_type="application/pdf"
            )
            
            # Document should still be created but with special status
            assert result is not None
            assert result.status == DocumentStatus.PENDING_BLOCKCHAIN


class TestDocumentRetrieval:
    """Test document retrieval with enhanced functionality"""
    
    @pytest.fixture
    def document_service(self, mock_services):
        return DocumentService(
            auth_service=mock_services["auth"],
            blockchain_service=mock_services["blockchain"],
            storage_service=mock_services["storage"]
        )
    
    @pytest.mark.asyncio
    async def test_get_document_with_proof_package(self, document_service, mock_services):
        """Test getting document with proof package information"""
        
        document_id = "doc_123"
        user_id = "user_123"
        
        with patch('services.document.get_documents_collection') as mock_collection:
            mock_db = AsyncMock()
            mock_collection.return_value = mock_db
            
            mock_doc = {
                "_id": document_id,
                "user_id": user_id,
                "name": "test_document.pdf",
                "hash": "hash123",
                "size": 1024,
                "file_type": "application/pdf",
                "status": DocumentStatus.COMPLETED,
                "created_at": datetime.now(timezone.utc),
                "updated_at": datetime.now(timezone.utc),
                "storage_path": "docs/test_document.pdf",
                "package_path": "packages/doc_123.zip",
                "blockchain_transaction_id": "tx_123",
                "blockchain_proof": "proof_data_base64",
                "metadata": {"author": "Test Author"}
            }
            mock_db.find_one.return_value = mock_doc
            
            result = await document_service.get_document(document_id, user_id)
            
            assert result is not None
            assert result.id == document_id
            assert result.package_path == "packages/doc_123.zip"
            assert result.blockchain_proof == "proof_data_base64"
            assert result.metadata["author"] == "Test Author"
    
    @pytest.mark.asyncio
    async def test_get_document_permission_check(self, document_service, mock_services):
        """Test document access permission checking"""
        
        document_id = "doc_123"
        unauthorized_user = "user_456"
        
        with patch('services.document.get_documents_collection') as mock_collection:
            mock_db = AsyncMock()
            mock_collection.return_value = mock_db
            
            # Document belongs to different user
            mock_doc = {
                "_id": document_id,
                "user_id": "user_123",  # Different from requesting user
                "name": "private_document.pdf",
                "status": DocumentStatus.COMPLETED
            }
            mock_db.find_one.return_value = mock_doc
            
            result = await document_service.get_document(document_id, unauthorized_user)
            
            # Should return None for unauthorized access
            assert result is None
    
    @pytest.mark.asyncio
    async def test_get_document_with_shared_access(self, document_service, mock_services):
        """Test document access with shared permissions"""
        
        document_id = "doc_123"
        shared_user = "user_456"
        
        with patch('services.document.get_documents_collection') as mock_collection:
            mock_db = AsyncMock()
            mock_collection.return_value = mock_db
            
            # Document with shared access
            mock_doc = {
                "_id": document_id,
                "user_id": "user_123",
                "name": "shared_document.pdf",
                "status": DocumentStatus.COMPLETED,
                "shared_with": ["user_456", "user_789"],  # Shared access list
                "share_permissions": {"user_456": ["read"], "user_789": ["read", "write"]}
            }
            mock_db.find_one.return_value = mock_doc
            
            result = await document_service.get_document(document_id, shared_user)
            
            assert result is not None
            assert result.id == document_id


class TestDocumentSearch:
    """Test enhanced document search functionality"""
    
    @pytest.fixture
    def document_service(self, mock_services):
        return DocumentService(
            auth_service=mock_services["auth"],
            blockchain_service=mock_services["blockchain"],
            storage_service=mock_services["storage"]
        )
    
    @pytest.mark.asyncio
    async def test_search_documents_with_filters(self, document_service, mock_services):
        """Test document search with multiple filters"""
        
        user_id = "user_123"
        
        # Mock search results
        mock_documents = [
            {
                "_id": f"doc_{i}",
                "user_id": user_id,
                "name": f"document_{i}.pdf",
                "hash": f"hash_{i}",
                "size": 1024 * (i + 1),
                "file_type": "application/pdf",
                "status": DocumentStatus.COMPLETED,
                "created_at": datetime.now(timezone.utc) - timedelta(days=i),
                "updated_at": datetime.now(timezone.utc),
                "metadata": {"category": "test", "priority": "high" if i % 2 == 0 else "low"},
                "tags": [f"tag_{i}", "common_tag"]
            }
            for i in range(5)
        ]
        
        with patch('services.document.get_documents_collection') as mock_collection:
            mock_db = AsyncMock()
            mock_collection.return_value = mock_db
            
            # Mock cursor operations
            mock_cursor = AsyncMock()
            mock_cursor.to_list.return_value = mock_documents
            mock_cursor.sort.return_value = mock_cursor
            mock_cursor.skip.return_value = mock_cursor
            mock_cursor.limit.return_value = mock_cursor
            mock_db.find.return_value = mock_cursor
            mock_db.count_documents.return_value = 5
            
            search_query = DocumentSearchQuery(
                page=1,
                page_size=10,
                query="document",
                status=DocumentStatus.COMPLETED,
                file_type="application/pdf",
                tags=["common_tag"],
                metadata_filters={"category": "test"},
                date_from=datetime.now(timezone.utc) - timedelta(days=10),
                date_to=datetime.now(timezone.utc),
                sort_by="created_at",
                sort_order="desc"
            )
            
            documents, total_count = await document_service.search_documents(
                user_id=user_id,
                query=search_query
            )
            
            assert len(documents) == 5
            assert total_count == 5
            assert all(isinstance(doc, DocumentResponse) for doc in documents)
            
            # Verify search query construction
            mock_db.find.assert_called_once()
            search_filter = mock_db.find.call_args[0][0]
            assert search_filter["user_id"] == user_id
            assert search_filter["status"] == DocumentStatus.COMPLETED
            assert search_filter["file_type"] == "application/pdf"
            assert "common_tag" in search_filter.get("tags", {}).get("$in", [])
    
    @pytest.mark.asyncio
    async def test_search_documents_full_text(self, document_service, mock_services):
        """Test full-text search functionality"""
        
        user_id = "user_123"
        
        with patch('services.document.get_documents_collection') as mock_collection:
            mock_db = AsyncMock()
            mock_collection.return_value = mock_db
            
            # Mock text search results with scores
            mock_documents = [
                {
                    "_id": "doc_1",
                    "user_id": user_id,
                    "name": "important_document.pdf",
                    "content_text": "This document contains important information",
                    "text_score": 1.5,
                    "status": DocumentStatus.COMPLETED
                },
                {
                    "_id": "doc_2", 
                    "user_id": user_id,
                    "name": "another_document.pdf",
                    "content_text": "Another document with some important data",
                    "text_score": 1.2,
                    "status": DocumentStatus.COMPLETED
                }
            ]
            
            mock_cursor = AsyncMock()
            mock_cursor.to_list.return_value = mock_documents
            mock_cursor.sort.return_value = mock_cursor
            mock_cursor.skip.return_value = mock_cursor
            mock_cursor.limit.return_value = mock_cursor
            mock_db.find.return_value = mock_cursor
            mock_db.count_documents.return_value = 2
            
            search_query = DocumentSearchQuery(
                page=1,
                page_size=10,
                query="important information",  # Full-text search
                use_text_search=True
            )
            
            documents, total_count = await document_service.search_documents(
                user_id=user_id,
                query=search_query
            )
            
            assert len(documents) == 2
            assert total_count == 2
            
            # Verify text search was used
            search_filter = mock_db.find.call_args[0][0]
            assert "$text" in search_filter
            assert search_filter["$text"]["$search"] == "important information"


class TestDocumentVerification:
    """Test document verification and proof generation"""
    
    @pytest.fixture
    def document_service(self, mock_services):
        return DocumentService(
            auth_service=mock_services["auth"],
            blockchain_service=mock_services["blockchain"],
            storage_service=mock_services["storage"]
        )
    
    @pytest.mark.asyncio
    async def test_verify_document_success(self, document_service, mock_services):
        """Test successful document verification"""
        
        document_id = "doc_123"
        user_id = "user_123"
        
        with patch('services.document.get_documents_collection') as mock_collection:
            mock_db = AsyncMock()
            mock_collection.return_value = mock_db
            
            mock_doc = {
                "_id": document_id,
                "user_id": user_id,
                "hash": "hash123",
                "blockchain_transaction_id": "tx_123",
                "blockchain_proof": "proof_data_base64",
                "status": DocumentStatus.COMPLETED
            }
            mock_db.find_one.return_value = mock_doc
            
            # Mock successful verification
            mock_services["blockchain"].verify_proof.return_value = ProofVerificationResult(
                is_valid=True,
                confirmations=6,
                block_height=750000,
                block_hash="block_hash_123",
                status=TransactionStatus.CONFIRMED,
                verification_time=datetime.now(timezone.utc)
            )
            
            result = await document_service.verify_document(document_id, user_id)
            
            assert result is not None
            assert result.is_valid is True
            assert result.confirmations == 6
            assert result.status == TransactionStatus.CONFIRMED
            
            # Verify blockchain service was called
            mock_services["blockchain"].verify_proof.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_verify_document_invalid_proof(self, document_service, mock_services):
        """Test document verification with invalid proof"""
        
        document_id = "doc_123"
        user_id = "user_123"
        
        with patch('services.document.get_documents_collection') as mock_collection:
            mock_db = AsyncMock()
            mock_collection.return_value = mock_db
            
            mock_doc = {
                "_id": document_id,
                "user_id": user_id,
                "hash": "hash123",
                "blockchain_transaction_id": "tx_123",
                "blockchain_proof": "invalid_proof_data",
                "status": DocumentStatus.COMPLETED
            }
            mock_db.find_one.return_value = mock_doc
            
            # Mock failed verification
            mock_services["blockchain"].verify_proof.return_value = ProofVerificationResult(
                is_valid=False,
                error="Proof verification failed",
                status=TransactionStatus.FAILED
            )
            
            result = await document_service.verify_document(document_id, user_id)
            
            assert result is not None
            assert result.is_valid is False
            assert "failed" in result.error.lower()
    
    @pytest.mark.asyncio
    async def test_generate_proof_package(self, document_service, mock_services):
        """Test generating comprehensive proof package"""
        
        document_id = "doc_123"
        user_id = "user_123"
        
        with patch('services.document.get_documents_collection') as mock_collection:
            mock_db = AsyncMock()
            mock_collection.return_value = mock_db
            
            mock_doc = {
                "_id": document_id,
                "user_id": user_id,
                "name": "test_document.pdf",
                "hash": "hash123",
                "blockchain_transaction_id": "tx_123",
                "blockchain_proof": "proof_data_base64",
                "package_path": "packages/doc_123.zip",
                "status": DocumentStatus.COMPLETED,
                "created_at": datetime.now(timezone.utc),
                "metadata": {"author": "Test Author"}
            }
            mock_db.find_one.return_value = mock_doc
            
            # Mock file retrieval
            mock_services["storage"].get_file.return_value = {
                "content": b"original file content",
                "info": MagicMock(size=1024, content_type="application/pdf")
            }
            
            # Mock proof package creation
            mock_services["storage"].store_file.return_value = MagicMock(
                file_path="packages/doc_123.zip",
                size=2048,
                etag="package_etag"
            )
            
            result = await document_service.generate_proof_package(document_id, user_id)
            
            assert result is not None
            assert isinstance(result, ProofPackageInfo)
            assert result.package_path == "packages/doc_123.zip"
            assert result.package_size == 2048
            
            # Verify proof package was stored
            mock_services["storage"].store_file.assert_called()


class TestDocumentStatistics:
    """Test document statistics and analytics"""
    
    @pytest.fixture
    def document_service(self, mock_services):
        return DocumentService(
            auth_service=mock_services["auth"],
            blockchain_service=mock_services["blockchain"],
            storage_service=mock_services["storage"]
        )
    
    @pytest.mark.asyncio
    async def test_get_user_statistics_comprehensive(self, document_service, mock_services):
        """Test comprehensive user statistics"""
        
        user_id = "user_123"
        
        with patch('services.document.get_documents_collection') as mock_collection:
            mock_db = AsyncMock()
            mock_collection.return_value = mock_db
            
            # Mock aggregation pipeline results
            mock_aggregation_results = [
                {
                    "_id": DocumentStatus.COMPLETED,
                    "count": 15,
                    "total_size": 1500000,
                    "avg_processing_time": 5000
                },
                {
                    "_id": DocumentStatus.PROCESSING,
                    "count": 3,
                    "total_size": 300000,
                    "avg_processing_time": None  # Still processing
                },
                {
                    "_id": DocumentStatus.FAILED,
                    "count": 2,
                    "total_size": 200000,
                    "avg_processing_time": 2000  # Failed quickly
                }
            ]
            
            mock_cursor = AsyncMock()
            mock_cursor.to_list.return_value = mock_aggregation_results
            mock_db.aggregate.return_value = mock_cursor
            
            stats = await document_service.get_user_statistics(user_id)
            
            assert isinstance(stats, DocumentStatistics)
            assert stats.total_documents == 20  # 15 + 3 + 2
            assert stats.completed_documents == 15
            assert stats.processing_documents == 3
            assert stats.failed_documents == 2
            assert stats.total_storage_bytes == 2000000  # Sum of all sizes
            assert stats.success_rate == 75.0  # 15/20 * 100
            assert stats.average_processing_time == 5000
    
    @pytest.mark.asyncio
    async def test_get_user_statistics_with_time_range(self, document_service, mock_services):
        """Test user statistics with specific time range"""
        
        user_id = "user_123"
        start_date = datetime.now(timezone.utc) - timedelta(days=30)
        end_date = datetime.now(timezone.utc)
        
        with patch('services.document.get_documents_collection') as mock_collection:
            mock_db = AsyncMock()
            mock_collection.return_value = mock_db
            
            mock_aggregation_results = [
                {
                    "_id": DocumentStatus.COMPLETED,
                    "count": 10,
                    "total_size": 1000000,
                    "recent_uploads": 8,
                    "this_week": 3
                }
            ]
            
            mock_cursor = AsyncMock()
            mock_cursor.to_list.return_value = mock_aggregation_results
            mock_db.aggregate.return_value = mock_cursor
            
            stats = await document_service.get_user_statistics(
                user_id, 
                start_date=start_date, 
                end_date=end_date
            )
            
            assert stats.total_documents == 10
            
            # Verify aggregation pipeline included date filter
            mock_db.aggregate.assert_called_once()
            pipeline = mock_db.aggregate.call_args[0][0]
            
            # Should have $match stage with date range
            match_stage = next((stage for stage in pipeline if "$match" in stage), None)
            assert match_stage is not None
            assert "created_at" in match_stage["$match"]


class TestDocumentWorkflowIntegration:
    """Test complete document workflow integration"""
    
    @pytest.fixture
    def document_service(self, mock_services):
        return DocumentService(
            auth_service=mock_services["auth"],
            blockchain_service=mock_services["blockchain"],
            storage_service=mock_services["storage"],
            notification_service=mock_services["notification"],
            audit_service=mock_services["audit"]
        )
    
    @pytest.mark.asyncio
    async def test_complete_document_lifecycle(self, document_service, mock_services):
        """Test complete document lifecycle from creation to verification"""
        
        user_id = "user_123"
        file_content = b"Important document content for testing complete lifecycle"
        
        # Step 1: Create document
        mock_services["storage"].store_file.return_value = MagicMock(
            file_path="docs/lifecycle_test.pdf",
            size=len(file_content),
            etag="etag123"
        )
        
        mock_services["blockchain"].create_timestamp.return_value = BlockchainTransaction(
            transaction_id="tx_lifecycle",
            document_hash=hashlib.sha256(file_content).hexdigest(),
            status=TransactionStatus.PENDING,
            blockchain_network="bitcoin",
            proof_type="opentimestamps"
        )
        
        with patch('services.document.get_documents_collection') as mock_collection:
            mock_db = AsyncMock()
            mock_collection.return_value = mock_db
            mock_db.insert_one.return_value = MagicMock(inserted_id="doc_lifecycle")
            
            # Mock document states throughout lifecycle
            document_states = [
                # Initial state after creation
                {
                    "_id": "doc_lifecycle",
                    "user_id": user_id,
                    "name": "lifecycle_test.pdf",
                    "hash": hashlib.sha256(file_content).hexdigest(),
                    "status": DocumentStatus.PROCESSING,
                    "blockchain_transaction_id": "tx_lifecycle",
                    "created_at": datetime.now(timezone.utc)
                },
                # After blockchain confirmation
                {
                    "_id": "doc_lifecycle",
                    "user_id": user_id,
                    "name": "lifecycle_test.pdf",
                    "hash": hashlib.sha256(file_content).hexdigest(),
                    "status": DocumentStatus.COMPLETED,
                    "blockchain_transaction_id": "tx_lifecycle",
                    "blockchain_proof": "confirmed_proof_data",
                    "package_path": "packages/doc_lifecycle.zip",
                    "created_at": datetime.now(timezone.utc),
                    "completed_at": datetime.now(timezone.utc)
                }
            ]
            
            mock_db.find_one.side_effect = document_states
            
            # Create document
            created_doc = await document_service.create_document(
                user_id=user_id,
                filename="lifecycle_test.pdf",
                file_content=file_content,
                content_type="application/pdf",
                metadata={"lifecycle": "test"}
            )
            
            assert created_doc is not None
            assert created_doc.status == DocumentStatus.PROCESSING
            
            # Step 2: Simulate blockchain confirmation
            # (This would normally be done by background job)
            await document_service.update_blockchain_status(
                "doc_lifecycle",
                TransactionStatus.CONFIRMED,
                "confirmed_proof_data"
            )
            
            # Step 3: Retrieve completed document
            completed_doc = await document_service.get_document("doc_lifecycle", user_id)
            
            assert completed_doc is not None
            assert completed_doc.status == DocumentStatus.COMPLETED
            assert completed_doc.blockchain_proof == "confirmed_proof_data"
            
            # Step 4: Verify document
            mock_services["blockchain"].verify_proof.return_value = ProofVerificationResult(
                is_valid=True,
                confirmations=6,
                status=TransactionStatus.CONFIRMED
            )
            
            verification_result = await document_service.verify_document("doc_lifecycle", user_id)
            
            assert verification_result.is_valid is True
            assert verification_result.confirmations == 6
            
            # Verify all notification and audit events were logged
            assert mock_services["notification"].send_document_notification.call_count >= 2
            assert mock_services["audit"].log_audit_event.call_count >= 3


class TestPerformanceOptimizations:
    """Test performance optimizations and monitoring"""
    
    @pytest.fixture
    def document_service(self, mock_services):
        return DocumentService(
            auth_service=mock_services["auth"],
            blockchain_service=mock_services["blockchain"],
            storage_service=mock_services["storage"]
        )
    
    def test_performance_stats_tracking(self, document_service):
        """Test performance statistics tracking"""
        
        # Simulate operations
        document_service._operation_stats["create"] = 10
        document_service._operation_stats["get"] = 25
        document_service._operation_stats["search"] = 5
        document_service._operation_stats["download"] = 8
        document_service._operation_stats["verify"] = 12
        
        stats = document_service.get_performance_stats()
        
        assert stats["operation_counts"]["create"] == 10
        assert stats["operation_counts"]["get"] == 25
        assert stats["operation_counts"]["search"] == 5
        assert stats["operation_counts"]["download"] == 8
        assert stats["operation_counts"]["verify"] == 12
        assert stats["optimizations_enabled"] is True
        assert "thread_pool_stats" in stats
        assert "cache_stats" in stats
    
    @pytest.mark.asyncio
    async def test_health_check_comprehensive(self, document_service, mock_services):
        """Test comprehensive health check"""
        
        with patch('services.document.get_documents_collection') as mock_collection:
            mock_db = AsyncMock()
            mock_collection.return_value = mock_db
            mock_db.count_documents.return_value = 100
            
            # Mock service health checks
            mock_services["blockchain"].health_check.return_value = {"status": "healthy"}
            mock_services["storage"].health_check.return_value = {"status": "healthy"}
            
            health = await document_service.health_check()
            
            assert health["status"] == "healthy"
            assert health["database_connection"] == "ok"
            assert health["document_count"] == 100
            assert "performance_stats" in health
            assert "service_dependencies" in health
            assert health["service_dependencies"]["blockchain"]["status"] == "healthy"
            assert health["service_dependencies"]["storage"]["status"] == "healthy"
    
    @pytest.mark.asyncio
    async def test_concurrent_operations_performance(self, document_service, mock_services):
        """Test performance under concurrent operations"""
        
        user_id = "user_concurrent"
        
        # Mock fast responses
        mock_services["storage"].store_file.return_value = MagicMock(
            file_path="docs/concurrent.pdf", size=1024, etag="etag"
        )
        
        mock_services["blockchain"].create_timestamp.return_value = BlockchainTransaction(
            transaction_id="tx_concurrent",
            document_hash="hash_concurrent",
            status=TransactionStatus.PENDING,
            blockchain_network="bitcoin",
            proof_type="opentimestamps"
        )
        
        with patch('services.document.get_documents_collection') as mock_collection:
            mock_db = AsyncMock()
            mock_collection.return_value = mock_db
            mock_db.insert_one.return_value = MagicMock(inserted_id="doc_concurrent")
            mock_db.find_one.return_value = {
                "_id": "doc_concurrent",
                "user_id": user_id,
                "status": DocumentStatus.PROCESSING
            }
            
            # Create multiple concurrent document creation tasks
            tasks = []
            for i in range(10):
                task = document_service.create_document(
                    user_id=user_id,
                    filename=f"concurrent_{i}.pdf",
                    file_content=f"Content {i}".encode(),
                    content_type="application/pdf"
                )
                tasks.append(task)
            
            start_time = time.time()
            results = await asyncio.gather(*tasks, return_exceptions=True)
            execution_time = time.time() - start_time
            
            # Should handle concurrent operations efficiently
            assert execution_time < 2.0  # Should complete within 2 seconds
            
            # All operations should succeed
            successful_results = [r for r in results if not isinstance(r, Exception)]
            assert len(successful_results) == 10


class TestErrorHandlingAndRecovery:
    """Test comprehensive error handling and recovery scenarios"""
    
    @pytest.fixture
    def document_service(self, mock_services):
        return DocumentService(
            auth_service=mock_services["auth"],
            blockchain_service=mock_services["blockchain"],
            storage_service=mock_services["storage"],
            notification_service=mock_services["notification"],
            audit_service=mock_services["audit"]
        )
    
    @pytest.mark.asyncio
    async def test_database_connection_failure_handling(self, document_service, mock_services):
        """Test handling of database connection failures"""
        
        with patch('services.document.get_documents_collection') as mock_collection:
            mock_collection.side_effect = Exception("Database connection failed")
            
            result = await document_service.get_document("doc_123", "user_123")
            
            assert result is None
            
            # Should log error through audit service
            mock_services["audit"].log_audit_event.assert_called()
    
    @pytest.mark.asyncio
    async def test_service_unavailable_graceful_degradation(self, document_service, mock_services):
        """Test graceful degradation when services are unavailable"""
        
        # Storage service unavailable
        mock_services["storage"].store_file.side_effect = Exception("Storage unavailable")
        # Blockchain service unavailable  
        mock_services["blockchain"].create_timestamp.side_effect = Exception("Blockchain unavailable")
        # Notification service unavailable
        mock_services["notification"].send_document_notification.side_effect = Exception("Notification unavailable")
        
        result = await document_service.create_document(
            user_id="user_123",
            filename="test.pdf",
            file_content=b"test content",
            content_type="application/pdf"
        )
        
        # Should fail gracefully without crashing
        assert result is None
        
        # Should attempt to log audit event even if other services fail
        mock_services["audit"].log_audit_event.assert_called()
    
    @pytest.mark.asyncio
    async def test_retry_mechanism_transient_failures(self, document_service, mock_services):
        """Test retry mechanism for transient failures"""
        
        call_count = 0
        
        def failing_storage(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count <= 2:
                raise Exception("Transient failure")
            return MagicMock(file_path="docs/retry_test.pdf", size=1024, etag="etag")
        
        mock_services["storage"].store_file.side_effect = failing_storage
        mock_services["blockchain"].create_timestamp.return_value = BlockchainTransaction(
            transaction_id="tx_retry",
            document_hash="hash_retry",
            status=TransactionStatus.PENDING,
            blockchain_network="bitcoin",
            proof_type="opentimestamps"
        )
        
        with patch('services.document.get_documents_collection') as mock_collection:
            mock_db = AsyncMock()
            mock_collection.return_value = mock_db
            mock_db.insert_one.return_value = MagicMock(inserted_id="doc_retry")
            mock_db.find_one.return_value = {
                "_id": "doc_retry",
                "user_id": "user_123",
                "status": DocumentStatus.PROCESSING
            }
            
            with patch('asyncio.sleep'):  # Speed up test
                result = await document_service.create_document(
                    user_id="user_123",
                    filename="retry_test.pdf",
                    file_content=b"retry content",
                    content_type="application/pdf"
                )
            
            # Should eventually succeed after retries
            assert result is not None
            assert call_count == 3  # Two failures + one success


if __name__ == "__main__":
    # Run tests with pytest
    pytest.main([__file__, "-v", "--tb=short"])