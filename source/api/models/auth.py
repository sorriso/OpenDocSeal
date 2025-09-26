"""
Path: infrastructure/source/api/models/auth.py
Version: 2
"""

from datetime import datetime, timezone
from typing import Optional, Dict, Any, List
from pydantic import BaseModel, Field, field_validator, EmailStr, ConfigDict

from .base import BaseDocument, TimestampMixin, UserRole, CommonValidators


class UserCreate(BaseModel):
    """Model for user creation"""
    
    # FIXED: Updated to use model_config
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "email": "user@example.com",
                "password": "SecurePass123!",
                "name": "John Doe",
                "organization": "Example Corp",
                "phone": "+1234567890"
            }
        }
    )
    
    email: EmailStr = Field(..., description="User email address")
    password: str = Field(..., min_length=8, max_length=100, description="User password")
    name: str = Field(..., min_length=1, max_length=100, description="User full name")
    organization: Optional[str] = Field(default=None, max_length=100, description="User organization")
    phone: Optional[str] = Field(default=None, description="User phone number")
    
    # FIXED: Updated validator syntax
    @field_validator("password")
    @classmethod
    def validate_password_strength(cls, v):
        """Validate password strength"""
        import re
        
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters long")
        
        if not re.search(r'[A-Z]', v):
            raise ValueError("Password must contain at least one uppercase letter")
        
        if not re.search(r'[a-z]', v):
            raise ValueError("Password must contain at least one lowercase letter")
        
        if not re.search(r'\d', v):
            raise ValueError("Password must contain at least one digit")
        
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', v):
            raise ValueError("Password must contain at least one special character")
        
        return v
    
    # FIXED: Updated validator syntax
    @field_validator("phone", mode="before")
    @classmethod
    def validate_phone_format(cls, v):
        """Validate phone number format"""
        if v:
            return CommonValidators.validate_phone(v)
        return v


class UserUpdate(BaseModel):
    """Model for user updates"""
    
    # FIXED: Updated to use model_config
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "name": "John Updated",
                "organization": "New Corp",
                "phone": "+1987654321"
            }
        }
    )
    
    name: Optional[str] = Field(default=None, min_length=1, max_length=100, description="User full name")
    organization: Optional[str] = Field(default=None, max_length=100, description="User organization")
    phone: Optional[str] = Field(default=None, description="User phone number")
    
    # FIXED: Updated validator syntax
    @field_validator("phone", mode="before")
    @classmethod
    def validate_phone_format(cls, v):
        """Validate phone number format"""
        if v:
            return CommonValidators.validate_phone(v)
        return v


class User(BaseDocument):
    """User model"""
    
    # FIXED: Updated to use model_config
    model_config = ConfigDict(
        populate_by_name=True,
        arbitrary_types_allowed=True,
        json_encoders={
            datetime: lambda v: v.isoformat()
        },
        json_schema_extra={
            "example": {
                "id": "507f1f77bcf86cd799439011",
                "email": "user@example.com",
                "name": "John Doe",
                "role": "user",
                "organization": "Example Corp",
                "phone": "+1234567890",
                "is_active": True,
                "email_verified": False,
                "created_at": "2023-01-01T00:00:00Z",
                "updated_at": "2023-01-01T00:00:00Z"
            }
        }
    )
    
    email: EmailStr = Field(..., description="User email address", unique=True)
    password_hash: str = Field(..., description="Hashed password")
    name: str = Field(..., min_length=1, max_length=100, description="User full name")
    role: UserRole = Field(default=UserRole.USER, description="User role")
    organization: Optional[str] = Field(default=None, max_length=100, description="User organization")
    phone: Optional[str] = Field(default=None, description="User phone number")
    is_active: bool = Field(default=True, description="User active status")
    email_verified: bool = Field(default=False, description="Email verification status")
    last_login: Optional[datetime] = Field(default=None, description="Last login timestamp")
    failed_login_attempts: int = Field(default=0, description="Failed login attempts counter")
    locked_until: Optional[datetime] = Field(default=None, description="Account locked until")
    
    # FIXED: Updated validator syntax
    @field_validator("phone", mode="before")
    @classmethod
    def validate_phone_format(cls, v):
        """Validate phone number format"""
        if v:
            return CommonValidators.validate_phone(v)
        return v


class UserLogin(BaseModel):
    """User login model"""
    
    # FIXED: Updated to use model_config
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "email": "user@example.com",
                "password": "SecurePass123!"
            }
        }
    )
    
    email: EmailStr = Field(..., description="User email address")
    password: str = Field(..., min_length=1, max_length=100, description="User password")


class UserResponse(BaseModel):
    """User response model (without sensitive data)"""
    
    # FIXED: Updated to use model_config
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "id": "507f1f77bcf86cd799439011",
                "email": "user@example.com",
                "name": "John Doe",
                "role": "user",
                "organization": "Example Corp",
                "phone": "+1234567890",
                "is_active": True,
                "email_verified": False,
                "created_at": "2023-01-01T00:00:00Z",
                "last_login": "2023-01-01T00:00:00Z"
            }
        }
    )
    
    id: str = Field(..., description="User ID")
    email: EmailStr = Field(..., description="User email address")
    name: str = Field(..., description="User full name")
    role: UserRole = Field(..., description="User role")
    organization: Optional[str] = Field(default=None, description="User organization")
    phone: Optional[str] = Field(default=None, description="User phone number")
    is_active: bool = Field(..., description="User active status")
    email_verified: bool = Field(..., description="Email verification status")
    created_at: datetime = Field(..., description="Creation timestamp")
    last_login: Optional[datetime] = Field(default=None, description="Last login timestamp")


class TokenResponse(BaseModel):
    """Token response model"""
    
    # FIXED: Updated to use model_config
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
                "refresh_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
                "token_type": "bearer",
                "expires_in": 1800,
                "user": {
                    "id": "507f1f77bcf86cd799439011",
                    "email": "user@example.com",
                    "name": "John Doe",
                    "role": "user"
                }
            }
        }
    )
    
    access_token: str = Field(..., description="Access token")
    refresh_token: str = Field(..., description="Refresh token")
    token_type: str = Field(default="bearer", description="Token type")
    expires_in: int = Field(..., description="Token expiration time in seconds")
    user: UserResponse = Field(..., description="User information")


class TokenRefresh(BaseModel):
    """Token refresh model"""
    
    # FIXED: Updated to use model_config
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "refresh_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..."
            }
        }
    )
    
    refresh_token: str = Field(..., description="Refresh token")


class PasswordReset(BaseModel):
    """Password reset request model"""
    
    # FIXED: Updated to use model_config
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "email": "user@example.com"
            }
        }
    )
    
    email: EmailStr = Field(..., description="User email address")


class PasswordChange(BaseModel):
    """Password change model"""
    
    # FIXED: Updated to use model_config
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "current_password": "CurrentPass123!",
                "new_password": "NewPass123!"
            }
        }
    )
    
    current_password: str = Field(..., min_length=1, max_length=100, description="Current password")
    new_password: str = Field(..., min_length=8, max_length=100, description="New password")
    
    # FIXED: Updated validator syntax
    @field_validator("new_password")
    @classmethod
    def validate_password_strength(cls, v):
        """Validate password strength"""
        import re
        
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters long")
        
        if not re.search(r'[A-Z]', v):
            raise ValueError("Password must contain at least one uppercase letter")
        
        if not re.search(r'[a-z]', v):
            raise ValueError("Password must contain at least one lowercase letter")
        
        if not re.search(r'\d', v):
            raise ValueError("Password must contain at least one digit")
        
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', v):
            raise ValueError("Password must contain at least one special character")
        
        return v


class APIKey(BaseDocument):
    """API Key model"""
    
    # FIXED: Updated to use model_config
    model_config = ConfigDict(
        populate_by_name=True,
        arbitrary_types_allowed=True,
        json_schema_extra={
            "example": {
                "id": "507f1f77bcf86cd799439011",
                "user_id": "507f1f77bcf86cd799439012",
                "name": "Production API Key",
                "key_hash": "hashed_key_value",
                "permissions": ["read", "write"],
                "is_active": True,
                "expires_at": "2024-01-01T00:00:00Z",
                "created_at": "2023-01-01T00:00:00Z"
            }
        }
    )
    
    user_id: str = Field(..., description="User ID that owns this API key")
    name: str = Field(..., min_length=1, max_length=100, description="API key name")
    key_hash: str = Field(..., description="Hashed API key value")
    permissions: List[str] = Field(default=[], description="API key permissions")
    is_active: bool = Field(default=True, description="API key active status")
    expires_at: Optional[datetime] = Field(default=None, description="API key expiration")
    last_used: Optional[datetime] = Field(default=None, description="Last usage timestamp")
    usage_count: int = Field(default=0, description="Usage counter")


class APIKeyCreate(BaseModel):
    """API Key creation model"""
    
    # FIXED: Updated to use model_config
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "name": "Production API Key",
                "permissions": ["read", "write"],
                "expires_in_days": 90
            }
        }
    )
    
    name: str = Field(..., min_length=1, max_length=100, description="API key name")
    permissions: List[str] = Field(default=[], description="API key permissions")
    expires_in_days: Optional[int] = Field(default=None, ge=1, le=365, description="Expiration in days")


class APIKeyResponse(BaseModel):
    """API Key response model"""
    
    # FIXED: Updated to use model_config
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "id": "507f1f77bcf86cd799439011",
                "name": "Production API Key",
                "key": "odseal_abc123...",
                "permissions": ["read", "write"],
                "expires_at": "2024-01-01T00:00:00Z",
                "created_at": "2023-01-01T00:00:00Z"
            }
        }
    )
    
    id: str = Field(..., description="API key ID")
    name: str = Field(..., description="API key name")
    key: str = Field(..., description="API key value (only shown once)")
    permissions: List[str] = Field(..., description="API key permissions")
    expires_at: Optional[datetime] = Field(default=None, description="API key expiration")
    created_at: datetime = Field(..., description="Creation timestamp")