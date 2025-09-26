"""
Path: infrastructure/source/api/models/__init__.py
Version: 4
"""

# Base models and utilities
from base import (
    # Base classes
    BaseDocument,
    TimestampMixin,
    ResponseModel,
    ErrorResponse,
    PaginationModel,
    PaginatedResponse,
    
    # Common models
    HashModel,
    FileInfoModel,
    ServiceHealthModel,
    HealthCheckModel,
    
    # Enums
    UserRole,
    DocumentStatus,
    TransactionStatus,
    AuditAction,
    
    # Validators utility
    CommonValidators,
    
    # Factory functions
    create_success_response,
    create_error_response,
    create_paginated_response
)

# Authentication and user models
from auth import (
    UserCreate,
    UserUpdate,
    User,
    UserLogin,
    UserResponse,
    TokenResponse,
    TokenRefresh,
    PasswordReset,
    PasswordChange,
    APIKey,
    APIKeyCreate,
    APIKeyResponse
)

# Extended user models
from user import (
    UserPreferences,
    UserQuota,
    UserUsage,
    UserProfile,
    UserActivityLog,
    UserInvitation,
    UserWithProfile,
    UserStats
)

# Document models
from document import (
    DocumentCreate,
    DocumentUpdate,
    Document,
    DocumentResponse,
    DocumentSearchFilter,
    DocumentStatistics,
    ProofPackageInfo
)

# Blockchain models
from blockchain import (
    BlockchainTransaction,
    BlockchainProof,
    BlockchainHealthStatus,
    TransactionStatistics,
    ProofVerificationRequest,
    ProofVerificationResult,
    
    # Enums
    BlockchainNetwork,
    ProofType
)

# Metadata models
from metadata import (
    MetadataField,
    MetadataSchema,
    MetadataTemplate,
    DocumentMetadata,
    MetadataSearchQuery,
    MetadataStatistics,
    MetadataValidationRule,
    
    # Enums
    MetadataType
)

# Model collections for easy access
AUTH_MODELS = [
    UserCreate, UserUpdate, User, UserLogin, UserResponse,
    TokenResponse, TokenRefresh, PasswordReset, PasswordChange,
    APIKey, APIKeyCreate, APIKeyResponse
]

USER_MODELS = [
    UserPreferences, UserQuota, UserUsage, UserProfile,
    UserActivityLog, UserInvitation, UserWithProfile, UserStats
]

DOCUMENT_MODELS = [
    DocumentCreate, DocumentUpdate, Document, DocumentResponse,
    DocumentSearchFilter, DocumentStatistics, ProofPackageInfo
]

BLOCKCHAIN_MODELS = [
    BlockchainTransaction, BlockchainProof, BlockchainHealthStatus,
    TransactionStatistics, ProofVerificationRequest, ProofVerificationResult
]

METADATA_MODELS = [
    MetadataField, MetadataSchema, MetadataTemplate, DocumentMetadata,
    MetadataSearchQuery, MetadataStatistics, MetadataValidationRule
]

BASE_MODELS = [
    BaseDocument, TimestampMixin, ResponseModel, ErrorResponse,
    PaginationModel, PaginatedResponse, HashModel, FileInfoModel,
    ServiceHealthModel, HealthCheckModel
]

ALL_MODELS = AUTH_MODELS + USER_MODELS + DOCUMENT_MODELS + BLOCKCHAIN_MODELS + METADATA_MODELS + BASE_MODELS

# Package metadata
__version__ = "2.1.0"
__description__ = "Pydantic v2.11.9 compatible models for OpenDocSeal API - Document notarization with blockchain timestamping"

# Export model categories for easy import
__all__ = [
    # Base exports
    "BaseDocument", "TimestampMixin", "ResponseModel", "ErrorResponse",
    "PaginationModel", "PaginatedResponse", "HashModel", "FileInfoModel",
    "ServiceHealthModel", "HealthCheckModel",
    
    # Enums
    "UserRole", "DocumentStatus", "TransactionStatus", "AuditAction",
    "BlockchainNetwork", "ProofType", "MetadataType",
    
    # Auth models
    "UserCreate", "UserUpdate", "User", "UserLogin", "UserResponse",
    "TokenResponse", "TokenRefresh", "PasswordReset", "PasswordChange",
    "APIKey", "APIKeyCreate", "APIKeyResponse",
    
    # User models
    "UserPreferences", "UserQuota", "UserUsage", "UserProfile",
    "UserActivityLog", "UserInvitation", "UserWithProfile", "UserStats",
    
    # Document models
    "DocumentCreate", "DocumentUpdate", "Document", "DocumentResponse",
    "DocumentSearchFilter", "DocumentStatistics", "ProofPackageInfo",
    
    # Blockchain models
    "BlockchainTransaction", "BlockchainProof", "BlockchainHealthStatus",
    "TransactionStatistics", "ProofVerificationRequest", "ProofVerificationResult",
    
    # Metadata models
    "MetadataField", "MetadataSchema", "MetadataTemplate", "DocumentMetadata",
    "MetadataSearchQuery", "MetadataStatistics", "MetadataValidationRule",
    
    # Utilities
    "CommonValidators", "create_success_response", "create_error_response", "create_paginated_response",
    
    # Model collections
    "AUTH_MODELS", "USER_MODELS", "DOCUMENT_MODELS", "BLOCKCHAIN_MODELS", "METADATA_MODELS", "BASE_MODELS", "ALL_MODELS"
]