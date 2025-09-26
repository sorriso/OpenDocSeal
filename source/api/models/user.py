"""
Path: infrastructure/source/api/models/user.py
Version: 4
"""

from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, Any, List
from pydantic import BaseModel, Field, field_validator, ConfigDict
from enum import Enum

from .base import BaseDocument, UserRole
from .auth import User


class UserPreferences(BaseModel):
    """User preferences model"""
    
    # FIXED: Updated to use model_config
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "language": "fr",
                "timezone": "Europe/Paris",
                "theme": "light",
                "notifications_email": True,
                "notifications_browser": True,
                "default_file_privacy": "private",
                "auto_generate_proofs": True
            }
        }
    )
    
    language: str = Field(default="fr", description="Preferred language")
    timezone: str = Field(default="Europe/Paris", description="User timezone")
    theme: str = Field(default="light", description="UI theme preference")
    notifications_email: bool = Field(default=True, description="Email notifications enabled")
    notifications_browser: bool = Field(default=True, description="Browser notifications enabled")
    default_file_privacy: str = Field(default="private", description="Default file privacy setting")
    auto_generate_proofs: bool = Field(default=True, description="Auto-generate proof packages")
    
    # FIXED: Updated validator syntax
    @field_validator("language")
    @classmethod
    def validate_language(cls, v):
        allowed_languages = ["fr", "en", "es", "de", "it"]
        if v not in allowed_languages:
            raise ValueError(f"Language must be one of: {allowed_languages}")
        return v
    
    # FIXED: Updated validator syntax
    @field_validator("theme")
    @classmethod
    def validate_theme(cls, v):
        allowed_themes = ["light", "dark", "auto"]
        if v not in allowed_themes:
            raise ValueError(f"Theme must be one of: {allowed_themes}")
        return v
    
    # FIXED: Updated validator syntax
    @field_validator("default_file_privacy")
    @classmethod
    def validate_privacy(cls, v):
        allowed_privacy = ["private", "public", "organization"]
        if v not in allowed_privacy:
            raise ValueError(f"Privacy setting must be one of: {allowed_privacy}")
        return v


class UserQuota(BaseModel):
    """User quota model"""
    
    # FIXED: Updated to use model_config
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "documents_per_month": 100,
                "storage_bytes": 1073741824,
                "api_calls_per_hour": 1000,
                "blockchain_operations_per_day": 50
            }
        }
    )
    
    documents_per_month: int = Field(default=100, ge=0, description="Maximum documents per month")
    storage_bytes: int = Field(default=1_073_741_824, ge=0, description="Maximum storage in bytes (1GB)")
    api_calls_per_hour: int = Field(default=1000, ge=0, description="Maximum API calls per hour")
    blockchain_operations_per_day: int = Field(default=50, ge=0, description="Maximum blockchain operations per day")


class UserUsage(BaseModel):
    """User usage tracking model"""
    
    # FIXED: Updated to use model_config
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "documents_this_month": 25,
                "storage_used_bytes": 268435456,
                "api_calls_this_hour": 150,
                "blockchain_operations_today": 12,
                "last_reset_date": "2023-01-01T00:00:00Z"
            }
        }
    )
    
    documents_this_month: int = Field(default=0, ge=0, description="Documents created this month")
    storage_used_bytes: int = Field(default=0, ge=0, description="Storage used in bytes")
    api_calls_this_hour: int = Field(default=0, ge=0, description="API calls made this hour")
    blockchain_operations_today: int = Field(default=0, ge=0, description="Blockchain operations today")
    last_reset_date: datetime = Field(default_factory=lambda: datetime.now(timezone.utc), description="Last reset date")


class UserProfile(BaseDocument):
    """Extended user profile model"""
    
    # FIXED: Updated to use model_config
    model_config = ConfigDict(
        populate_by_name=True,
        arbitrary_types_allowed=True,
        json_schema_extra={
            "example": {
                "id": "507f1f77bcf86cd799439011",
                "user_id": "507f1f77bcf86cd799439012",
                "preferences": {
                    "language": "fr",
                    "theme": "light"
                },
                "quota": {
                    "documents_per_month": 100,
                    "storage_bytes": 1073741824
                },
                "usage": {
                    "documents_this_month": 25,
                    "storage_used_bytes": 268435456
                }
            }
        }
    )
    
    user_id: str = Field(..., description="Associated user ID")
    preferences: UserPreferences = Field(default_factory=UserPreferences, description="User preferences")
    quota: UserQuota = Field(default_factory=UserQuota, description="User quotas")
    usage: UserUsage = Field(default_factory=UserUsage, description="Current usage")
    notes: Optional[str] = Field(default=None, max_length=2000, description="Admin notes")
    tags: List[str] = Field(default=[], description="User tags for organization")
    
    def is_quota_exceeded(self, quota_type: str) -> bool:
        """Check if a specific quota is exceeded"""
        quota_map = {
            "documents": (self.usage.documents_this_month, self.quota.documents_per_month),
            "storage": (self.usage.storage_used_bytes, self.quota.storage_bytes),
            "api_calls": (self.usage.api_calls_this_hour, self.quota.api_calls_per_hour),
            "blockchain": (self.usage.blockchain_operations_today, self.quota.blockchain_operations_per_day)
        }
        
        if quota_type not in quota_map:
            return False
        
        current, limit = quota_map[quota_type]
        return current >= limit
    
    def get_quota_usage_percentage(self, quota_type: str) -> float:
        """Get quota usage as percentage"""
        quota_map = {
            "documents": (self.usage.documents_this_month, self.quota.documents_per_month),
            "storage": (self.usage.storage_used_bytes, self.quota.storage_bytes),
            "api_calls": (self.usage.api_calls_this_hour, self.quota.api_calls_per_hour),
            "blockchain": (self.usage.blockchain_operations_today, self.quota.blockchain_operations_per_day)
        }
        
        if quota_type not in quota_map:
            return 0.0
        
        current, limit = quota_map[quota_type]
        if limit == 0:
            return 0.0
        
        return min((current / limit) * 100, 100.0)


class UserActivityLog(BaseDocument):
    """User activity log model"""
    
    # FIXED: Updated to use model_config
    model_config = ConfigDict(
        populate_by_name=True,
        arbitrary_types_allowed=True,
        json_schema_extra={
            "example": {
                "id": "507f1f77bcf86cd799439011",
                "user_id": "507f1f77bcf86cd799439012",
                "action": "document_create",
                "resource_id": "507f1f77bcf86cd799439013",
                "ip_address": "192.168.1.1",
                "user_agent": "Mozilla/5.0...",
                "metadata": {"document_name": "test.pdf"},
                "timestamp": "2023-01-01T00:00:00Z"
            }
        }
    )
    
    user_id: str = Field(..., description="User ID")
    action: str = Field(..., description="Action performed")
    resource_type: Optional[str] = Field(default=None, description="Type of resource")
    resource_id: Optional[str] = Field(default=None, description="Resource ID")
    ip_address: Optional[str] = Field(default=None, description="Client IP address")
    user_agent: Optional[str] = Field(default=None, description="Client user agent")
    metadata: Dict[str, Any] = Field(default={}, description="Additional metadata")
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc), description="Action timestamp")


class UserInvitation(BaseDocument):
    """User invitation model"""
    
    # FIXED: Updated to use model_config
    model_config = ConfigDict(
        populate_by_name=True,
        arbitrary_types_allowed=True,
        json_schema_extra={
            "example": {
                "id": "507f1f77bcf86cd799439011",
                "invited_by": "507f1f77bcf86cd799439012",
                "email": "newuser@example.com",
                "role": "user",
                "organization": "Example Corp",
                "expires_at": "2023-02-01T00:00:00Z",
                "is_used": False,
                "created_at": "2023-01-01T00:00:00Z"
            }
        }
    )
    
    invited_by: str = Field(..., description="User ID who sent the invitation")
    email: str = Field(..., description="Invited email address")
    role: UserRole = Field(default=UserRole.USER, description="Assigned role")
    organization: Optional[str] = Field(default=None, description="Organization")
    token: str = Field(..., description="Invitation token")
    expires_at: datetime = Field(..., description="Invitation expiration")
    is_used: bool = Field(default=False, description="Whether invitation was used")
    used_at: Optional[datetime] = Field(default=None, description="When invitation was used")
    used_by_user_id: Optional[str] = Field(default=None, description="User ID who used the invitation")
    
    def is_expired(self) -> bool:
        """Check if invitation is expired"""
        return datetime.now(timezone.utc) > self.expires_at
    
    def is_valid(self) -> bool:
        """Check if invitation is valid (not used and not expired)"""
        return not self.is_used and not self.is_expired()


# Extended User Models
class UserWithProfile(User):
    """User model with profile information"""
    
    # FIXED: Updated to use model_config
    model_config = ConfigDict(
        populate_by_name=True,
        arbitrary_types_allowed=True,
        json_schema_extra={
            "example": {
                "id": "507f1f77bcf86cd799439011",
                "email": "user@example.com",
                "name": "John Doe",
                "role": "user",
                "profile": {
                    "preferences": {"language": "fr"},
                    "quota": {"documents_per_month": 100},
                    "usage": {"documents_this_month": 25}
                }
            }
        }
    )
    
    profile: Optional[UserProfile] = Field(default=None, description="User profile")


class UserStats(BaseModel):
    """User statistics model"""
    
    # FIXED: Updated to use model_config
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "total_documents": 150,
                "documents_this_month": 25,
                "storage_used_mb": 256,
                "total_api_calls": 5000,
                "blockchain_operations": 75,
                "last_activity": "2023-01-01T00:00:00Z",
                "registration_date": "2022-01-01T00:00:00Z",
                "days_active": 365
            }
        }
    )
    
    total_documents: int = Field(default=0, description="Total documents created")
    documents_this_month: int = Field(default=0, description="Documents created this month")
    storage_used_mb: float = Field(default=0.0, description="Storage used in MB")
    total_api_calls: int = Field(default=0, description="Total API calls made")
    blockchain_operations: int = Field(default=0, description="Total blockchain operations")
    last_activity: Optional[datetime] = Field(default=None, description="Last activity timestamp")
    registration_date: datetime = Field(..., description="User registration date")
    days_active: int = Field(default=0, description="Number of days user has been active")