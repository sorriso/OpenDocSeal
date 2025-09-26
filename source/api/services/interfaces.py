"""
Path: infrastructure/source/api/services/interfaces.py
Version: 4 - FIXED ASYNC SIGNATURES
"""

from abc import ABC, abstractmethod
from typing import Optional, Dict, Any, List, BinaryIO, Tuple
from datetime import datetime

from ..models.auth import (
    User, UserCreate, UserUpdate, LoginRequest, TokenResponse, 
    PasswordChangeRequest, APIKeyCreate, APIKeyResponse
)
from ..models.document import (
    Document, DocumentCreate, DocumentUpdate, DocumentResponse,
    DocumentSearchQuery, DocumentUploadResponse, DocumentDownloadResponse,
    DocumentVerificationRequest, DocumentVerificationResponse,
    DocumentStatistics
)
from ..models.blockchain import (
    BlockchainProofResponse, BlockchainHealthStatus, TransactionStatistics,
    BlockchainTransaction
)


class AuthServiceInterface(ABC):
    """Authentication service interface with fixed signatures"""
    
    @abstractmethod
    async def create_user(self, user_data: UserCreate) -> User:
        """Create a new user"""
        pass
    
    @abstractmethod
    async def get_user_by_id(self, user_id: str) -> Optional[User]:
        """Get user by ID"""
        pass
    
    @abstractmethod
    async def get_user_by_email(self, email: str) -> Optional[User]:
        """Get user by email"""
        pass
    
    @abstractmethod
    async def update_user(self, user_id: str, user_data: UserUpdate) -> User:
        """Update user information"""
        pass
    
    @abstractmethod
    async def authenticate_user(
        self, 
        login_request: LoginRequest, 
        client_ip: Optional[str] = None
    ) -> Optional[TokenResponse]:
        """
        FIXED: Authenticate user and return tokens
        
        Args:
            login_request: LoginRequest object containing email and password
            client_ip: Optional client IP address for logging
            
        Returns:
            TokenResponse if authentication successful, None otherwise
        """
        pass
    
    @abstractmethod
    async def refresh_token(self, refresh_token: str) -> Optional[TokenResponse]:
        """Refresh access token"""
        pass
    
    @abstractmethod
    async def get_current_user(self, token: str) -> Optional[User]:
        """Get current user from token"""
        pass
    
    @abstractmethod
    async def verify_token(self, token: str) -> Optional[Dict[str, Any]]:
        """Verify JWT token"""
        pass
    
    @abstractmethod
    async def change_password(
        self, user_id: str, password_change: PasswordChangeRequest
    ) -> bool:
        """Change user password"""
        pass
    
    @abstractmethod
    async def create_api_key(
        self, user_id: str, api_key_data: APIKeyCreate
    ) -> APIKeyResponse:
        """Create API key for user"""
        pass
    
    @abstractmethod
    async def verify_api_key(self, api_key: str) -> Optional[Dict[str, Any]]:
        """Verify API key"""
        pass
    
    @abstractmethod
    async def revoke_api_key(self, user_id: str, api_key_id: str) -> bool:
        """Revoke API key"""
        pass
    
    @abstractmethod
    async def get_user_api_keys(self, user_id: str) -> List[APIKeyResponse]:
        """Get user's API keys"""
        pass
    
    @abstractmethod
    async def update_last_activity(self, user_id: str) -> None:
        """Update user's last activity timestamp"""
        pass
    
    @abstractmethod
    async def get_all_users(self) -> List[User]:
        """Get all users (admin only)"""
        pass
    
    @abstractmethod
    async def get_users_list(
        self,
        page: int = 1,
        page_size: int = 20,
        search_email: Optional[str] = None,
        role_filter: Optional[str] = None
    ) -> Tuple[List[User], int]:
        """Get paginated users list"""
        pass


class BlockchainServiceInterface(ABC):
    """Blockchain service interface"""
    
    @abstractmethod
    async def create_timestamp(
        self, 
        document_hash: str,
        user_id: str,
        document_id: Optional[str] = None
    ) -> Optional[BlockchainProofResponse]:
        """Create blockchain timestamp for document hash"""
        pass
    
    @abstractmethod
    async def get_proof(
        self, transaction_id: str, user_id: str
    ) -> Optional[BlockchainProofResponse]:
        """Get blockchain proof by transaction ID"""
        pass
    
    @abstractmethod
    async def verify_proof(
        self, 
        document_hash: str, 
        proof_data: Dict[str, Any],
        user_id: str
    ) -> bool:
        """Verify blockchain proof"""
        pass
    
    @abstractmethod
    async def get_transaction_status(
        self, transaction_id: str, user_id: str
    ) -> str:
        """Get transaction status"""
        pass
    
    @abstractmethod
    async def get_user_transactions(
        self,
        user_id: str,
        page: int = 1,
        page_size: int = 20,
        status_filter: Optional[str] = None
    ) -> Tuple[List[BlockchainTransaction], int]:
        """Get user's blockchain transactions"""
        pass
    
    @abstractmethod
    async def get_transaction_statistics(self, user_id: str) -> TransactionStatistics:
        """Get transaction statistics for user"""
        pass
    
    @abstractmethod
    async def health_check(self) -> BlockchainHealthStatus:
        """Check blockchain service health"""
        pass
    
    @abstractmethod
    async def cleanup_resources(self) -> None:
        """Cleanup service resources"""
        pass


class StorageServiceInterface(ABC):
    """Storage service interface"""
    
    @abstractmethod
    async def store_file(
        self,
        file_data: BinaryIO,
        file_path: str,
        content_type: str = "application/octet-stream",
        metadata: Optional[Dict[str, str]] = None
    ) -> str:
        """Store file and return storage path"""
        pass
    
    @abstractmethod
    async def get_file(self, file_path: str) -> Optional[BinaryIO]:
        """Retrieve file by path"""
        pass
    
    @abstractmethod
    async def delete_file(self, file_path: str) -> bool:
        """Delete file"""
        pass
    
    @abstractmethod
    async def file_exists(self, file_path: str) -> bool:
        """Check if file exists"""
        pass
    
    @abstractmethod
    async def get_file_info(self, file_path: str) -> Optional[Dict[str, Any]]:
        """Get file information"""
        pass
    
    @abstractmethod
    async def generate_presigned_url(
        self,
        file_path: str,
        expires_in: int = 3600,
        method: str = "GET"
    ) -> Optional[str]:
        """Generate presigned URL for file access"""
        pass
    
    @abstractmethod
    async def list_files(
        self,
        prefix: str = "",
        limit: int = 100,
        recursive: bool = False
    ) -> List[Dict[str, Any]]:
        """List files with optional prefix filter"""
        pass
    
    @abstractmethod
    async def health_check(self) -> Dict[str, Any]:
        """Check storage service health"""
        pass
    
    @abstractmethod
    async def cleanup_temp_files(self, max_age_hours: int = 24) -> Dict[str, int]:
        """Clean up temporary files"""
        pass


class DocumentServiceInterface(ABC):
    """Document service interface with fixed signatures"""
    
    @abstractmethod
    async def create_document(
        self,
        user_id: str,
        document_data: DocumentCreate,
        file_content: Optional[BinaryIO] = None
    ) -> DocumentUploadResponse:
        """
        FIXED: Create a new document with optional file upload
        
        Args:
            user_id: ID of the user creating the document
            document_data: Document creation data
            file_content: Optional file content to store
            
        Returns:
            DocumentUploadResponse with document details and processing info
        """
        pass
    
    @abstractmethod
    async def get_document(self, document_id: str, user_id: str) -> Optional[DocumentResponse]:
        """Get document by ID"""
        pass
    
    @abstractmethod
    async def update_document(
        self, document_id: str, user_id: str, document_update: DocumentUpdate
    ) -> Optional[DocumentResponse]:
        """Update document metadata"""
        pass
    
    @abstractmethod
    async def delete_document(self, document_id: str, user_id: str) -> bool:
        """Delete document"""
        pass
    
    @abstractmethod
    async def search_documents(
        self, 
        user_id: str,
        query: DocumentSearchQuery
    ) -> Tuple[List[DocumentResponse], int]:
        """
        FIXED: Search documents with pagination
        
        Args:
            user_id: ID of the user searching
            query: Search query parameters
            
        Returns:
            Tuple of (documents_list, total_count)
        """
        pass
    
    @abstractmethod
    async def download_document(
        self, 
        document_id: str, 
        user_id: str
    ) -> Optional[DocumentDownloadResponse]:
        """Get document download response (URL or file content)"""
        pass
    
    @abstractmethod
    async def verify_document(
        self, verification_request: DocumentVerificationRequest
    ) -> DocumentVerificationResponse:
        """Verify document authenticity"""
        pass
    
    @abstractmethod
    async def get_user_statistics(self, user_id: str) -> DocumentStatistics:
        """Get document statistics for user"""
        pass
    
    @abstractmethod
    async def wait_for_completion(
        self, document_id: str, user_id: str, timeout: int = 300
    ) -> Document:
        """Wait for document processing completion"""
        pass
    
    @abstractmethod
    async def wait_for_blockchain_confirmation(
        self, document_id: str, user_id: str, timeout: int = 3600
    ) -> Document:
        """Wait for blockchain confirmation"""
        pass
    
    @abstractmethod
    async def health_check(self) -> Dict[str, Any]:
        """Check document service health"""
        pass
    
    @abstractmethod
    async def get_performance_stats(self) -> Dict[str, Any]:
        """FIXED: Get service performance statistics (now async)"""
        pass


class NotificationServiceInterface(ABC):
    """Notification service interface"""
    
    @abstractmethod
    async def send_email_verification(self, user_id: str, email: str) -> bool:
        """Send email verification"""
        pass
    
    @abstractmethod
    async def send_password_reset(self, user_id: str, email: str, reset_token: str) -> bool:
        """Send password reset email"""
        pass
    
    @abstractmethod
    async def send_document_notification(
        self, user_id: str, document_id: str, event_type: str
    ) -> bool:
        """Send document event notification"""
        pass
    
    @abstractmethod
    async def send_security_alert(self, user_id: str, alert_type: str, details: Dict[str, Any]) -> bool:
        """Send security alert"""
        pass


class AuditServiceInterface(ABC):
    """Audit service interface"""
    
    @abstractmethod
    async def log_event(
        self,
        action: str,
        user_id: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        ip_address: Optional[str] = None,
        correlation_id: Optional[str] = None
    ) -> None:
        """Log audit event"""
        pass
    
    @abstractmethod
    async def get_user_audit_log(
        self,
        user_id: str,
        page: int = 1,
        page_size: int = 20,
        action_filter: Optional[str] = None
    ) -> Tuple[List[Dict[str, Any]], int]:
        """Get user audit log"""
        pass
    
    @abstractmethod
    async def get_system_audit_log(
        self,
        page: int = 1,
        page_size: int = 20,
        action_filter: Optional[str] = None,
        date_from: Optional[datetime] = None,
        date_to: Optional[datetime] = None
    ) -> Tuple[List[Dict[str, Any]], int]:
        """Get system audit log"""
        pass
    
    @abstractmethod
    async def cleanup_old_logs(self, max_age_days: int = 90) -> int:
        """Clean up old audit logs"""
        pass


# Service registry for dependency injection
class ServiceRegistry:
    """Service registry for managing service instances"""
    
    def __init__(self):
        self._services: Dict[str, Any] = {}
    
    def register(self, interface_class: type, implementation: Any) -> None:
        """Register service implementation for interface"""
        self._services[interface_class.__name__] = implementation
    
    def get(self, interface_class: type) -> Any:
        """Get service implementation for interface"""
        return self._services.get(interface_class.__name__)
    
    def clear(self) -> None:
        """Clear all registered services"""
        self._services.clear()


# Global service registry instance
service_registry = ServiceRegistry()