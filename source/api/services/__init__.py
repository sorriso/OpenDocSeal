"""
Path: infrastructure/source/api/services/__init__.py
Version: 2 - ADDED MISSING SERVICES
"""

from interfaces import (
    AuthServiceInterface, BlockchainServiceInterface, StorageServiceInterface,
    DocumentServiceInterface, NotificationServiceInterface, AuditServiceInterface
)

from auth import AuthService
from blockchain import BlockchainService
from storage import StorageService
from document import DocumentService
from notification import NotificationService  # NEW: Added missing service
from audit import AuditService  # NEW: Added missing service

# Import mock services
from mocks.auth_mock import AuthMockService
from mocks.blockchain_mock import BlockchainMockService
from mocks.storage_mock import StorageMockService

__all__ = [
    # Interfaces
    "AuthServiceInterface",
    "BlockchainServiceInterface", 
    "StorageServiceInterface",
    "DocumentServiceInterface",
    "NotificationServiceInterface",  # FIXED: Now has implementation
    "AuditServiceInterface",         # FIXED: Now has implementation
    
    # Production services
    "AuthService",
    "BlockchainService", 
    "StorageService",
    "DocumentService",
    "NotificationService",  # NEW: Added
    "AuditService",         # NEW: Added
    
    # Mock services
    "AuthMockService",
    "BlockchainMockService",
    "StorageMockService"
]