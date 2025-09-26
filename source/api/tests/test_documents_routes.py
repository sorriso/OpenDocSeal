"""
Path: infrastructure/source/api/tests/test_documents_routes.py
Version: 1 - Documents Routes End-to-End Tests
"""

import pytest
import json
import io
from datetime import datetime, timezone, timedelta
from unittest.mock import AsyncMock, MagicMock, patch
from typing import Dict, Any, List

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi.testclient import TestClient
from fastapi import status, UploadFile

# Import the FastAPI app
from main import app
from models.document import (
    DocumentCreate, DocumentResponse, DocumentUploadResponse, DocumentDownloadResponse,
    DocumentStatistics, DocumentVerificationRequest, DocumentVerificationResponse
)
from models.blockchain import BlockchainProofResponse
from models.base import DocumentStatus, TransactionStatus, ResponseModel, PaginatedResponse
from models.auth import User, UserRole


class TestDocumentsRoutesSetup:
    """Test documents routes setup and configuration"""
    
    @pytest.fixture
    def client(self):
        """Create test client"""
        return TestClient(app)
    
    @pytest.fixture
    def mock_user(self):
        """Mock authenticated user"""
        return User(
            id="user_123",
            email="test@example.com",
            name="Test User",
            role=UserRole.USER,
            is_active=True,
            email_verified=True,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
            last_login=None
        )
    
    @pytest.fixture
    def auth_headers(self):
        """Authentication headers for requests"""
        return {
            "Authorization": "Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.test_token",
            "Content-Type": "application/json"
        }
    
    @pytest.fixture
    def sample_document_data(self):
        """Sample document creation data"""
        return {
            "name": "test_document.pdf",
            "hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "size": 1024,
            "file_type": "application/pdf",
            "metadata": {"author": "Test User", "category": "contract"},
            "tags": ["test", "contract"]
        }
    
    @pytest.fixture
    def mock_document_response(self):
        """Mock document response"""
        return DocumentResponse(
            id="doc_123",
            name="test_document.pdf",
            hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            size=1024,
            file_type="application/pdf",
            status=DocumentStatus.COMPLETED,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
            metadata={"author": "Test User"},
            tags=["test"],
            storage_path="storage/doc_123.pdf",
            package_path="packages/doc_123.zip",
            blockchain_transaction_id="tx_123",
            processing_time_ms=500
        )
    
    @pytest.fixture
    def mock_upload_response(self):
        """Mock upload response"""
        return DocumentUploadResponse(
            id="doc_123",
            status=DocumentStatus.PROCESSING,
            message="Document created successfully",
            processing_time_ms=250
        )


class TestSecureFileUpload:
    """Test secure file upload endpoint"""
    
    def test_upload_file_success(self, client, mock_user, mock_upload_response):
        """Test successful secure file upload"""
        
        # Create test file
        test_file_content = b"Test PDF content here"
        test_file = io.BytesIO(test_file_content)
        
        with patch('routes.documents.get_current_active_user') as mock_get_user, \
             patch('routes.documents.validate_file_upload') as mock_validate, \
             patch('routes.documents.get_document_service') as mock_get_service, \
             patch('routes.documents.secure_filename') as mock_secure_name, \
             patch('routes.documents.log_audit_event') as mock_audit, \
             patch('routes.documents.get_correlation_id') as mock_correlation:
            
            # Setup mocks
            mock_get_user.return_value = mock_user
            mock_validate.return_value = {
                'valid': True,
                'hash': 'calculated_hash_123',
                'detected_mime': 'application/pdf',
                'threats': []
            }
            mock_secure_name.return_value = "test_document.pdf"
            mock_correlation.return_value = "test-correlation-123"
            
            mock_doc_service = AsyncMock()
            mock_get_service.return_value = mock_doc_service
            mock_doc_service.create_document.return_value = mock_upload_response
            
            # Prepare multipart data
            files = {"file": ("test.pdf", test_file, "application/pdf")}
            data = {"metadata": json.dumps({"category": "test"})}
            
            # Make request
            response = client.post(
                "/api/v1/documents/upload",
                files=files,
                data=data,
                headers={"Authorization": "Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.test_token"}
            )
            
            # Verify response
            assert response.status_code == status.HTTP_201_CREATED
            
            response_data = response.json()
            assert response_data["id"] == "doc_123"
            assert response_data["status"] == DocumentStatus.PROCESSING
            assert "processing_time_ms" in response_data
            
            # Verify file validation was called
            mock_validate.assert_called_once()
            
            # Verify document service was called with correct parameters
            mock_doc_service.create_document.assert_called_once()
            call_kwargs = mock_doc_service.create_document.call_args[1]
            assert call_kwargs["user_id"] == "user_123"
            assert call_kwargs["document_data"].name == "test_document.pdf"
            assert call_kwargs["document_data"].hash == "calculated_hash_123"
            assert call_kwargs["document_data"].detected_mime == "application/pdf"
    
    def test_upload_file_validation_failure(self, client, mock_user):
        """Test file upload with validation failure"""
        
        test_file_content = b"Malicious file content"
        test_file = io.BytesIO(test_file_content)
        
        with patch('routes.documents.get_current_active_user') as mock_get_user, \
             patch('routes.documents.validate_file_upload') as mock_validate, \
             patch('routes.documents.get_correlation_id') as mock_correlation:
            
            mock_get_user.return_value = mock_user
            mock_validate.return_value = {
                'valid': False,
                'threats': ['Malware detected', 'Invalid MIME type']
            }
            mock_correlation.return_value = "test-correlation-123"
            
            files = {"file": ("malicious.exe", test_file, "application/octet-stream")}
            
            response = client.post(
                "/api/v1/documents/upload",
                files=files,
                headers={"Authorization": "Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.test_token"}
            )
            
            assert response.status_code == status.HTTP_400_BAD_REQUEST
            assert "File validation failed" in response.json()["detail"]
            assert "Malware detected" in response.json()["detail"]
    
    def test_upload_file_unauthorized(self, client):
        """Test file upload without authentication"""
        
        test_file = io.BytesIO(b"test content")
        files = {"file": ("test.pdf", test_file, "application/pdf")}
        
        response = client.post("/api/v1/documents/upload", files=files)
        
        assert response.status_code == status.HTTP_403_FORBIDDEN


class TestDocumentCreation:
    """Test document creation endpoint (metadata only)"""
    
    def test_create_document_success(self, client, mock_user, sample_document_data, mock_upload_response, auth_headers):
        """Test successful document creation"""
        
        with patch('routes.documents.get_current_active_user') as mock_get_user, \
             patch('routes.documents.get_document_service') as mock_get_service, \
             patch('routes.documents.get_settings') as mock_settings, \
             patch('routes.documents.get_correlation_id') as mock_correlation:
            
            # Setup mocks
            mock_get_user.return_value = mock_user
            mock_correlation.return_value = "test-correlation-123"
            
            mock_settings_obj = MagicMock()
            mock_settings_obj.max_file_size = 100 * 1024 * 1024  # 100MB
            mock_settings_obj.allowed_file_types = ["application/pdf"]
            mock_settings.return_value = mock_settings_obj
            
            mock_doc_service = AsyncMock()
            mock_get_service.return_value = mock_doc_service
            mock_doc_service.create_document.return_value = mock_upload_response
            
            # Make request
            response = client.post(
                "/api/v1/documents/",
                json=sample_document_data,
                headers=auth_headers
            )
            
            # Verify response
            assert response.status_code == status.HTTP_201_CREATED
            
            response_data = response.json()
            assert response_data["id"] == "doc_123"
            assert response_data["status"] == DocumentStatus.PROCESSING
            
            # Verify service was called correctly
            mock_doc_service.create_document.assert_called_once()
            call_kwargs = mock_doc_service.create_document.call_args[1]
            assert call_kwargs["user_id"] == "user_123"
            assert call_kwargs["file_content"] is None  # No file for metadata-only
    
    def test_create_document_file_too_large(self, client, mock_user, sample_document_data, auth_headers):
        """Test document creation with file too large"""
        
        sample_document_data["size"] = 200 * 1024 * 1024  # 200MB
        
        with patch('routes.documents.get_current_active_user') as mock_get_user, \
             patch('routes.documents.get_settings') as mock_settings, \
             patch('routes.documents.get_correlation_id') as mock_correlation:
            
            mock_get_user.return_value = mock_user
            mock_correlation.return_value = "test-correlation-123"
            
            mock_settings_obj = MagicMock()
            mock_settings_obj.max_file_size = 100 * 1024 * 1024  # 100MB limit
            mock_settings.return_value = mock_settings_obj
            
            response = client.post(
                "/api/v1/documents/",
                json=sample_document_data,
                headers=auth_headers
            )
            
            assert response.status_code == status.HTTP_413_REQUEST_ENTITY_TOO_LARGE
            assert "File too large" in response.json()["detail"]
    
    def test_create_document_invalid_file_type(self, client, mock_user, sample_document_data, auth_headers):
        """Test document creation with invalid file type"""
        
        sample_document_data["file_type"] = "application/exe"
        
        with patch('routes.documents.get_current_active_user') as mock_get_user, \
             patch('routes.documents.get_settings') as mock_settings, \
             patch('routes.documents.get_correlation_id') as mock_correlation:
            
            mock_get_user.return_value = mock_user
            mock_correlation.return_value = "test-correlation-123"
            
            mock_settings_obj = MagicMock()
            mock_settings_obj.allowed_file_types = ["application/pdf", "image/jpeg"]
            mock_settings.return_value = mock_settings_obj
            
            response = client.post(
                "/api/v1/documents/",
                json=sample_document_data,
                headers=auth_headers
            )
            
            assert response.status_code == status.HTTP_400_BAD_REQUEST
            assert "File type 'application/exe' not allowed" in response.json()["detail"]


class TestDocumentRetrieval:
    """Test document retrieval endpoints"""
    
    def test_list_documents_success(self, client, mock_user, auth_headers):
        """Test successful document listing with pagination"""
        
        mock_documents = [
            DocumentResponse(
                id=f"doc_{i}",
                name=f"document_{i}.pdf",
                hash=f"hash_{i}",
                size=1024,
                file_type="application/pdf",
                status=DocumentStatus.COMPLETED,
                created_at=datetime.now(timezone.utc),
                updated_at=datetime.now(timezone.utc)
            )
            for i in range(3)
        ]
        
        with patch('routes.documents.get_current_active_user') as mock_get_user, \
             patch('routes.documents.get_document_service') as mock_get_service, \
             patch('routes.documents.get_correlation_id') as mock_correlation:
            
            mock_get_user.return_value = mock_user
            mock_correlation.return_value = "test-correlation-123"
            
            mock_doc_service = AsyncMock()
            mock_get_service.return_value = mock_doc_service
            mock_doc_service.search_documents.return_value = (mock_documents, 3)
            
            # Make request
            response = client.get(
                "/api/v1/documents/?page=1&page_size=10",
                headers=auth_headers
            )
            
            # Verify response
            assert response.status_code == status.HTTP_200_OK
            
            response_data = response.json()
            assert response_data["total"] == 3
            assert response_data["page"] == 1
            assert response_data["page_size"] == 10
            assert response_data["total_pages"] == 1
            assert len(response_data["items"]) == 3
            
            # Verify service was called correctly
            mock_doc_service.search_documents.assert_called_once()
            call_kwargs = mock_doc_service.search_documents.call_args[1]
            assert call_kwargs["user_id"] == "user_123"
            assert call_kwargs["query"].page == 1
            assert call_kwargs["query"].page_size == 10
    
    def test_get_document_success(self, client, mock_user, mock_document_response, auth_headers):
        """Test successful document retrieval by ID"""
        
        with patch('routes.documents.get_current_active_user') as mock_get_user, \
             patch('routes.documents.get_document_service') as mock_get_service, \
             patch('routes.documents.get_correlation_id') as mock_correlation:
            
            mock_get_user.return_value = mock_user
            mock_correlation.return_value = "test-correlation-123"
            
            mock_doc_service = AsyncMock()
            mock_get_service.return_value = mock_doc_service
            mock_doc_service.get_document.return_value = mock_document_response
            
            response = client.get(
                "/api/v1/documents/doc_123",
                headers=auth_headers
            )
            
            assert response.status_code == status.HTTP_200_OK
            
            response_data = response.json()
            assert response_data["id"] == "doc_123"
            assert response_data["name"] == "test_document.pdf"
            assert response_data["status"] == DocumentStatus.COMPLETED
            
            # Verify service was called correctly
            mock_doc_service.get_document.assert_called_once_with("doc_123", "user_123")
    
    def test_get_document_not_found(self, client, mock_user, auth_headers):
        """Test document retrieval when document not found"""
        
        with patch('routes.documents.get_current_active_user') as mock_get_user, \
             patch('routes.documents.get_document_service') as mock_get_service, \
             patch('routes.documents.get_correlation_id') as mock_correlation:
            
            mock_get_user.return_value = mock_user
            mock_correlation.return_value = "test-correlation-123"
            
            mock_doc_service = AsyncMock()
            mock_get_service.return_value = mock_doc_service
            mock_doc_service.get_document.return_value = None
            
            response = client.get(
                "/api/v1/documents/nonexistent",
                headers=auth_headers
            )
            
            assert response.status_code == status.HTTP_404_NOT_FOUND
            assert "Document not found" in response.json()["detail"]


class TestDocumentUpdate:
    """Test document update endpoint"""
    
    def test_update_document_success(self, client, mock_user, mock_document_response, auth_headers):
        """Test successful document update"""
        
        update_data = {
            "metadata": {"author": "Updated Author", "category": "updated"},
            "tags": ["updated", "test"]
        }
        
        updated_document = DocumentResponse(
            id="doc_123",
            name="test_document.pdf",
            hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            size=1024,
            file_type="application/pdf",
            status=DocumentStatus.COMPLETED,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
            metadata={"author": "Updated Author", "category": "updated"},
            tags=["updated", "test"],
            storage_path="storage/doc_123.pdf",
            package_path="packages/doc_123.zip",
            blockchain_transaction_id="tx_123"
        )
        
        with patch('routes.documents.get_current_active_user') as mock_get_user, \
             patch('routes.documents.get_document_service') as mock_get_service, \
             patch('routes.documents.log_audit_event') as mock_audit, \
             patch('routes.documents.get_correlation_id') as mock_correlation:
            
            mock_get_user.return_value = mock_user
            mock_correlation.return_value = "test-correlation-123"
            
            mock_doc_service = AsyncMock()
            mock_get_service.return_value = mock_doc_service
            mock_doc_service.update_document.return_value = updated_document
            
            response = client.put(
                "/api/v1/documents/doc_123",
                json=update_data,
                headers=auth_headers
            )
            
            assert response.status_code == status.HTTP_200_OK
            
            response_data = response.json()
            assert response_data["metadata"]["author"] == "Updated Author"
            assert "updated" in response_data["tags"]
            
            # Verify service was called correctly
            mock_doc_service.update_document.assert_called_once()
            call_args = mock_doc_service.update_document.call_args[0]
            assert call_args[0] == "doc_123"
            assert call_args[1] == "user_123"


class TestDocumentDeletion:
    """Test document deletion endpoint"""
    
    def test_delete_document_success(self, client, mock_user, auth_headers):
        """Test successful document deletion"""
        
        with patch('routes.documents.get_current_active_user') as mock_get_user, \
             patch('routes.documents.get_document_service') as mock_get_service, \
             patch('routes.documents.log_audit_event') as mock_audit, \
             patch('routes.documents.get_correlation_id') as mock_correlation:
            
            mock_get_user.return_value = mock_user
            mock_correlation.return_value = "test-correlation-123"
            
            mock_doc_service = AsyncMock()
            mock_get_service.return_value = mock_doc_service
            mock_doc_service.delete_document.return_value = True
            
            response = client.delete(
                "/api/v1/documents/doc_123",
                headers=auth_headers
            )
            
            assert response.status_code == status.HTTP_200_OK
            
            response_data = response.json()
            assert response_data["success"] is True
            assert response_data["message"] == "Document deleted successfully"
            
            # Verify service was called correctly
            mock_doc_service.delete_document.assert_called_once_with("doc_123", "user_123")
    
    def test_delete_document_not_found(self, client, mock_user, auth_headers):
        """Test document deletion when document not found"""
        
        with patch('routes.documents.get_current_active_user') as mock_get_user, \
             patch('routes.documents.get_document_service') as mock_get_service, \
             patch('routes.documents.get_correlation_id') as mock_correlation:
            
            mock_get_user.return_value = mock_user
            mock_correlation.return_value = "test-correlation-123"
            
            mock_doc_service = AsyncMock()
            mock_get_service.return_value = mock_doc_service
            mock_doc_service.delete_document.return_value = False
            
            response = client.delete(
                "/api/v1/documents/nonexistent",
                headers=auth_headers
            )
            
            assert response.status_code == status.HTTP_404_NOT_FOUND
            assert "Document not found" in response.json()["detail"]


class TestDocumentDownload:
    """Test document download endpoint"""
    
    def test_download_document_success(self, client, mock_user, auth_headers):
        """Test successful document download"""
        
        mock_download_response = DocumentDownloadResponse(
            document_id="doc_123",
            download_url="https://storage.example.com/download/doc_123",
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
            size=1024
        )
        
        with patch('routes.documents.get_current_active_user') as mock_get_user, \
             patch('routes.documents.get_document_service') as mock_get_service, \
             patch('routes.documents.log_audit_event') as mock_audit, \
             patch('routes.documents.get_correlation_id') as mock_correlation:
            
            mock_get_user.return_value = mock_user
            mock_correlation.return_value = "test-correlation-123"
            
            mock_doc_service = AsyncMock()
            mock_get_service.return_value = mock_doc_service
            mock_doc_service.download_document.return_value = mock_download_response
            
            response = client.get(
                "/api/v1/documents/doc_123/download",
                headers=auth_headers
            )
            
            assert response.status_code == status.HTTP_200_OK
            
            response_data = response.json()
            assert response_data["document_id"] == "doc_123"
            assert response_data["download_url"] == "https://storage.example.com/download/doc_123"
            assert response_data["size"] == 1024
            
            # Verify service was called correctly
            mock_doc_service.download_document.assert_called_once_with("doc_123", "user_123")


class TestBlockchainProof:
    """Test blockchain proof endpoint"""
    
    def test_get_document_proof_success(self, client, mock_user, mock_document_response, auth_headers):
        """Test successful blockchain proof retrieval"""
        
        mock_proof_response = BlockchainProofResponse(
            transaction_id="tx_123",
            document_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            status=TransactionStatus.CONFIRMED,
            submitted_at=datetime.now(timezone.utc),
            confirmed_at=datetime.now(timezone.utc),
            proof_data={"merkle_root": "root123", "proof_path": []},
            transaction_hash="btc_tx_456",
            block_height=750000,
            confirmation_count=6
        )
        
        with patch('routes.documents.get_current_active_user') as mock_get_user, \
             patch('routes.documents.get_document_service') as mock_get_service, \
             patch('routes.documents.get_blockchain_service') as mock_get_blockchain, \
             patch('routes.documents.get_correlation_id') as mock_correlation:
            
            mock_get_user.return_value = mock_user
            mock_correlation.return_value = "test-correlation-123"
            
            mock_doc_service = AsyncMock()
            mock_get_service.return_value = mock_doc_service
            mock_doc_service.get_document.return_value = mock_document_response
            
            mock_blockchain_service = AsyncMock()
            mock_get_blockchain.return_value = mock_blockchain_service
            mock_blockchain_service.get_proof.return_value = mock_proof_response
            
            response = client.get(
                "/api/v1/documents/doc_123/proof",
                headers=auth_headers
            )
            
            assert response.status_code == status.HTTP_200_OK
            
            response_data = response.json()
            assert response_data["transaction_id"] == "tx_123"
            assert response_data["status"] == TransactionStatus.CONFIRMED
            assert response_data["transaction_hash"] == "btc_tx_456"
            assert response_data["block_height"] == 750000
            
            # Verify services were called correctly
            mock_doc_service.get_document.assert_called_once_with("doc_123", "user_123")
            mock_blockchain_service.get_proof.assert_called_once_with("tx_123", "user_123")
    
    def test_get_document_proof_not_available(self, client, mock_user, auth_headers):
        """Test proof retrieval when blockchain proof not available"""
        
        document_without_blockchain = DocumentResponse(
            id="doc_123",
            name="test_document.pdf",
            hash="hash123",
            size=1024,
            file_type="application/pdf",
            status=DocumentStatus.COMPLETED,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
            blockchain_transaction_id=None  # No blockchain transaction
        )
        
        with patch('routes.documents.get_current_active_user') as mock_get_user, \
             patch('routes.documents.get_document_service') as mock_get_service, \
             patch('routes.documents.get_correlation_id') as mock_correlation:
            
            mock_get_user.return_value = mock_user
            mock_correlation.return_value = "test-correlation-123"
            
            mock_doc_service = AsyncMock()
            mock_get_service.return_value = mock_doc_service
            mock_doc_service.get_document.return_value = document_without_blockchain
            
            response = client.get(
                "/api/v1/documents/doc_123/proof",
                headers=auth_headers
            )
            
            assert response.status_code == status.HTTP_404_NOT_FOUND
            assert "Blockchain proof not available" in response.json()["detail"]


class TestDocumentVerification:
    """Test document verification endpoint"""
    
    def test_verify_document_success(self, client):
        """Test successful document verification"""
        
        verification_request = {
            "hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "proof_data": {"merkle_root": "root123"}
        }
        
        mock_verification_response = DocumentVerificationResponse(
            is_valid=True,
            document_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            verified_at=datetime.now(timezone.utc),
            blockchain_status=TransactionStatus.CONFIRMED,
            verification_details={"status": "valid", "confirmations": 6}
        )
        
        with patch('routes.documents.get_document_service') as mock_get_service, \
             patch('routes.documents.get_correlation_id') as mock_correlation:
            
            mock_correlation.return_value = "test-correlation-123"
            
            mock_doc_service = AsyncMock()
            mock_get_service.return_value = mock_doc_service
            mock_doc_service.verify_document.return_value = mock_verification_response
            
            response = client.post(
                "/api/v1/documents/verify",
                json=verification_request,
                headers={"Content-Type": "application/json"}
            )
            
            assert response.status_code == status.HTTP_200_OK
            
            response_data = response.json()
            assert response_data["is_valid"] is True
            assert response_data["blockchain_status"] == TransactionStatus.CONFIRMED
            
            # Verify service was called correctly
            mock_doc_service.verify_document.assert_called_once()


class TestDocumentStatistics:
    """Test document statistics endpoint"""
    
    def test_get_user_statistics_success(self, client, mock_user, auth_headers):
        """Test successful user statistics retrieval"""
        
        mock_statistics = DocumentStatistics(
            total_documents=25,
            completed_documents=20,
            processing_documents=3,
            failed_documents=2,
            total_storage_bytes=50 * 1024 * 1024,  # 50MB
            success_rate=80.0
        )
        
        with patch('routes.documents.get_current_active_user') as mock_get_user, \
             patch('routes.documents.get_document_service') as mock_get_service, \
             patch('routes.documents.get_correlation_id') as mock_correlation:
            
            mock_get_user.return_value = mock_user
            mock_correlation.return_value = "test-correlation-123"
            
            mock_doc_service = AsyncMock()
            mock_get_service.return_value = mock_doc_service
            mock_doc_service.get_user_statistics.return_value = mock_statistics
            
            response = client.get(
                "/api/v1/documents/statistics",
                headers=auth_headers
            )
            
            assert response.status_code == status.HTTP_200_OK
            
            response_data = response.json()
            assert response_data["total_documents"] == 25
            assert response_data["completed_documents"] == 20
            assert response_data["processing_documents"] == 3
            assert response_data["failed_documents"] == 2
            assert response_data["success_rate"] == 80.0
            
            # Verify service was called correctly
            mock_doc_service.get_user_statistics.assert_called_once_with("user_123")


class TestErrorHandling:
    """Test error handling scenarios"""
    
    def test_unauthorized_access(self, client):
        """Test endpoints without authentication"""
        
        endpoints = [
            ("GET", "/api/v1/documents/"),
            ("POST", "/api/v1/documents/"),
            ("GET", "/api/v1/documents/doc_123"),
            ("PUT", "/api/v1/documents/doc_123"),
            ("DELETE", "/api/v1/documents/doc_123"),
            ("GET", "/api/v1/documents/doc_123/download"),
            ("GET", "/api/v1/documents/doc_123/proof"),
            ("GET", "/api/v1/documents/statistics")
        ]
        
        for method, endpoint in endpoints:
            if method == "GET":
                response = client.get(endpoint)
            elif method == "POST":
                response = client.post(endpoint, json={})
            elif method == "PUT":
                response = client.put(endpoint, json={})
            elif method == "DELETE":
                response = client.delete(endpoint)
            
            assert response.status_code == status.HTTP_403_FORBIDDEN
    
    def test_service_error_handling(self, client, mock_user, auth_headers):
        """Test handling of service errors"""
        
        with patch('routes.documents.get_current_active_user') as mock_get_user, \
             patch('routes.documents.get_document_service') as mock_get_service, \
             patch('routes.documents.get_correlation_id') as mock_correlation:
            
            mock_get_user.return_value = mock_user
            mock_correlation.return_value = "test-correlation-123"
            
            mock_doc_service = AsyncMock()
            mock_get_service.return_value = mock_doc_service
            mock_doc_service.get_document.side_effect = Exception("Service unavailable")
            
            response = client.get(
                "/api/v1/documents/doc_123",
                headers=auth_headers
            )
            
            assert response.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR
            assert "Failed to retrieve document" in response.json()["detail"]


if __name__ == "__main__":
    # Run tests with pytest
    pytest.main([__file__, "-v"])