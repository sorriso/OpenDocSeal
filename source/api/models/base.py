"""
Path: infrastructure/source/api/models/base.py
Version: 3
"""

from datetime import datetime, timezone
from typing import Any, Dict, Optional, List, Union, Annotated
from pydantic import BaseModel, Field, field_validator, ConfigDict
from pydantic_core import core_schema
from bson import ObjectId
from enum import Enum
import re


class PyObjectId(ObjectId):
    """Custom ObjectId class for Pydantic v2 compatibility"""
    
    @classmethod
    def __get_pydantic_core_schema__(cls, source_type, handler):
        """FIXED: New method for Pydantic v2 core schema"""
        return core_schema.no_info_plain_validator_function(
            cls.validate,
            serialization=core_schema.plain_serializer_function(str)
        )
    
    @classmethod
    def validate(cls, v):
        """Validate ObjectId"""
        if isinstance(v, ObjectId):
            return v
        if isinstance(v, str) and ObjectId.is_valid(v):
            return ObjectId(v)
        raise ValueError("Invalid ObjectId")


# Enums
class UserRole(str, Enum):
    """User roles in the system"""
    ADMIN = "admin"
    MANAGER = "manager"
    USER = "user"
    READONLY = "readonly"
    API_ONLY = "api_only"


class DocumentStatus(str, Enum):
    """Document processing status"""
    DRAFT = "draft"
    UPLOADING = "uploading"
    PROCESSING = "processing"
    PENDING = "pending"
    COMPLETED = "completed"
    ERROR = "error"
    EXPIRED = "expired"


class TransactionStatus(str, Enum):
    """Blockchain transaction status"""
    PENDING = "pending"
    SUBMITTED = "submitted"
    CONFIRMED = "confirmed"
    FAILED = "failed"
    EXPIRED = "expired"


class AuditAction(str, Enum):
    """Audit log action types"""
    # Authentication
    LOGIN = "login"
    LOGOUT = "logout"
    LOGIN_FAILED = "login_failed"
    PASSWORD_CHANGE = "password_change"
    PASSWORD_RESET = "password_reset"
    
    # User management
    USER_CREATE = "user_create"
    USER_UPDATE = "user_update"
    USER_DELETE = "user_delete"
    USER_ACTIVATE = "user_activate"
    USER_DEACTIVATE = "user_deactivate"
    
    # Document operations
    DOCUMENT_CREATE = "document_create"
    DOCUMENT_UPDATE = "document_update"
    DOCUMENT_DELETE = "document_delete"
    DOCUMENT_VIEW = "document_view"
    DOCUMENT_DOWNLOAD = "document_download"
    DOCUMENT_UPLOAD = "document_upload"
    DOCUMENT_VERIFY = "document_verify"
    
    # Proof operations
    PROOF_GENERATE = "proof_generate"
    PROOF_DOWNLOAD = "proof_download"
    PROOF_VERIFY = "proof_verify"
    
    # API operations
    API_KEY_CREATE = "api_key_create"
    API_KEY_UPDATE = "api_key_update"
    API_KEY_DELETE = "api_key_delete"
    API_CALL = "api_call"
    
    # Settings
    SETTINGS_UPDATE = "settings_update"
    QUOTA_UPDATE = "quota_update"
    
    # Security events
    SECURITY_EVENT = "security_event"
    SUSPICIOUS_ACTIVITY = "suspicious_activity"
    
    # System events
    SYSTEM_STARTUP = "system_startup"
    SYSTEM_SHUTDOWN = "system_shutdown"
    SYSTEM_ERROR = "system_error"


# Base Models
class BaseDocument(BaseModel):
    """Base document model with common fields"""
    
    # FIXED: Updated to use model_config instead of Config class
    model_config = ConfigDict(
        populate_by_name=True,
        arbitrary_types_allowed=True,
        json_encoders={
            ObjectId: str,
            datetime: lambda v: v.isoformat()
        }
    )
    
    id: Optional[PyObjectId] = Field(default_factory=PyObjectId, alias="_id")
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    
    def model_dump(self, **kwargs) -> Dict[str, Any]:
        """FIXED: Override model_dump method to handle ObjectId serialization"""
        d = super().model_dump(**kwargs)
        if "_id" in d:
            d["id"] = str(d.pop("_id"))
        return d


class TimestampMixin(BaseModel):
    """Mixin for timestamp fields"""
    
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    
    # FIXED: Updated validator syntax
    @field_validator("created_at", "updated_at", mode="before")
    @classmethod
    def validate_timestamps(cls, v):
        if isinstance(v, str):
            return datetime.fromisoformat(v.replace("Z", "+00:00"))
        return v


class ResponseModel(BaseModel):
    """Base response model"""
    
    # FIXED: Updated to use model_config
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "success": True,
                "message": "Operation completed successfully",
                "data": {"key": "value"}
            }
        }
    )
    
    success: bool = Field(default=True, description="Request success status")
    message: Optional[str] = Field(default=None, description="Response message")
    data: Optional[Dict[str, Any]] = Field(default=None, description="Response data")


class ErrorResponse(BaseModel):
    """Error response model"""
    
    # FIXED: Updated to use model_config
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "success": False,
                "error": "ValidationError",
                "message": "Invalid input parameters",
                "details": {"field": "email", "issue": "Invalid format"},
                "correlation_id": "req-123-456-789"
            }
        }
    )
    
    success: bool = Field(default=False, description="Request success status")
    error: str = Field(..., description="Error type")
    message: str = Field(..., description="Error message")
    details: Optional[Dict[str, Any]] = Field(default=None, description="Error details")
    correlation_id: Optional[str] = Field(default=None, description="Request correlation ID")


class PaginationModel(BaseModel):
    """Pagination parameters model"""
    
    # FIXED: Updated to use model_config
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "page": 1,
                "page_size": 20,
                "sort_by": "created_at",
                "sort_order": "desc"
            }
        }
    )
    
    page: int = Field(default=1, ge=1, description="Page number (1-based)")
    page_size: int = Field(default=20, ge=1, le=100, description="Items per page")
    sort_by: Optional[str] = Field(default=None, description="Field to sort by")
    sort_order: str = Field(default="desc", description="Sort order (asc, desc)")
    
    # FIXED: Updated validator syntax
    @field_validator("sort_order")
    @classmethod
    def validate_sort_order(cls, v):
        allowed = ["asc", "desc", "ascending", "descending"]
        if v.lower() not in allowed:
            raise ValueError("Sort order must be 'asc', 'desc', 'ascending', or 'descending'")
        return v.lower()


class PaginatedResponse(BaseModel):
    """Paginated response model"""
    
    # FIXED: Updated to use model_config
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "items": [],
                "total": 0,
                "page": 1,
                "page_size": 20,
                "total_pages": 0,
                "has_next": False,
                "has_previous": False
            }
        }
    )
    
    items: List[Any] = Field(..., description="List of items")
    total: int = Field(..., description="Total number of items")
    page: int = Field(..., description="Current page number")
    page_size: int = Field(..., description="Items per page")
    total_pages: int = Field(..., description="Total number of pages")
    has_next: bool = Field(..., description="Has next page")
    has_previous: bool = Field(..., description="Has previous page")


# File and Hash Models
class HashModel(BaseModel):
    """Hash model for document integrity"""
    
    # FIXED: Updated to use model_config
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "sha256": "a1b2c3d4e5f6...",
                "algorithm": "SHA256"
            }
        }
    )
    
    sha256: str = Field(..., min_length=64, max_length=64, description="SHA256 hash")
    algorithm: str = Field(default="SHA256", description="Hash algorithm")
    
    # FIXED: Updated validator syntax
    @field_validator("sha256")
    @classmethod
    def validate_hash_format(cls, v):
        if not re.match(r'^[a-fA-F0-9]{64}$', v):
            raise ValueError("SHA256 hash must be 64 hexadecimal characters")
        return v.lower()


class FileInfoModel(BaseModel):
    """File information model"""
    
    # FIXED: Updated to use model_config
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "name": "document.pdf",
                "size": 1024,
                "type": "application/pdf",
                "hash": "a1b2c3d4e5f6..."
            }
        }
    )
    
    name: str = Field(..., min_length=1, max_length=255, description="File name")
    size: int = Field(..., ge=0, description="File size in bytes")
    type: str = Field(..., description="MIME type")
    hash: str = Field(..., min_length=64, max_length=64, description="SHA256 hash")
    
    # FIXED: Updated validator syntax
    @field_validator("hash")
    @classmethod
    def validate_hash_format(cls, v):
        if not re.match(r'^[a-fA-F0-9]{64}$', v):
            raise ValueError("SHA256 hash must be 64 hexadecimal characters")
        return v.lower()


# Health Check Models
class ServiceHealthModel(BaseModel):
    """Service health status model"""
    
    # FIXED: Updated to use model_config
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "name": "database",
                "status": "healthy",
                "response_time": 0.05,
                "details": {"connections": 10}
            }
        }
    )
    
    name: str = Field(..., description="Service name")
    status: str = Field(..., description="Service status")
    response_time: Optional[float] = Field(default=None, description="Response time in seconds")
    details: Optional[Dict[str, Any]] = Field(default=None, description="Additional service details")


class HealthCheckModel(BaseModel):
    """Health check response model"""
    
    # FIXED: Updated to use model_config
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "status": "healthy",
                "timestamp": "2025-01-01T00:00:00Z",
                "uptime": 3600,
                "version": "1.0.0"
            }
        }
    )
    
    status: str = Field(..., description="Overall health status")
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc), description="Check timestamp")
    uptime: Optional[float] = Field(default=None, description="Uptime in seconds")
    version: Optional[str] = Field(default=None, description="Application version")
    services: Optional[List[ServiceHealthModel]] = Field(default=None, description="Individual service statuses")


# Common validators utility class
class CommonValidators:
    """Common validation utilities"""
    
    @staticmethod
    def validate_phone(phone: str) -> str:
        """Validate phone number format"""
        # Remove all non-digit characters
        cleaned = re.sub(r'[^\d+]', '', phone)
        
        # Check if it matches common phone patterns
        if re.match(r'^\+?[1-9]\d{7,14}$', cleaned):
            return cleaned
        
        raise ValueError("Invalid phone number format")
    
    @staticmethod
    def validate_url(url: str) -> str:
        """Validate URL format"""
        import urllib.parse
        
        try:
            result = urllib.parse.urlparse(url)
            if not all([result.scheme, result.netloc]):
                raise ValueError("Invalid URL format")
            return url
        except Exception:
            raise ValueError("Invalid URL format")