"""
Path: infrastructure/source/api/dependencies.py
Version: 6 - FIXED CRITICAL RECURSION
"""

import logging
import uuid
from datetime import datetime, timezone
from typing import Annotated, Optional, Dict, Any
from functools import lru_cache

from fastapi import Depends, HTTPException, status, Request, Header
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

# FIXED: Improved structlog import handling for 25.4.0+
try:
    import structlog
    from structlog import contextvars
    STRUCTLOG_AVAILABLE = True
except ImportError:
    STRUCTLOG_AVAILABLE = False
    structlog = None
    contextvars = None

from .config import get_settings
from .models.auth import User
from .models.base import UserRole
from .services.interfaces import (
    AuthServiceInterface, BlockchainServiceInterface, StorageServiceInterface,
    DocumentServiceInterface, NotificationServiceInterface, AuditServiceInterface
)
from .factories.service_factory import get_service_factory, get_test_service_factory
from .utils.logging import set_correlation_context, clear_correlation_context
from .utils.security import extract_bearer_token, verify_api_key_format
from .utils.rate_limiting import RateLimitResult
from .utils.file_security import get_file_validator, FileSecurityValidator  # NEW: File security
from .utils.sso_auth import authenticate_sso_user  # NEW: SSO authentication
from .database import test_hooks

logger = logging.getLogger(__name__)
settings = get_settings()
security = HTTPBearer()


# Service Dependencies - FIXED: Removed recursion, renamed function
@lru_cache()
def get_service_factory_dependency():
    """FIXED: Get cached service factory instance without recursion"""
    if settings.test_mode:
        return get_test_service_factory()
    return get_service_factory()  # This imports from factories.service_factory module


def get_auth_service() -> AuthServiceInterface:
    """Get authentication service instance"""
    return get_service_factory_dependency().create_auth_service()


def get_blockchain_service() -> BlockchainServiceInterface:
    """Get blockchain service instance"""  
    return get_service_factory_dependency().create_blockchain_service()


def get_storage_service() -> StorageServiceInterface:
    """Get storage service instance"""
    return get_service_factory_dependency().create_storage_service()


def get_document_service() -> DocumentServiceInterface:
    """Get document service instance"""
    return get_service_factory_dependency().create_document_service()


# NEW: Additional service dependencies
def get_notification_service() -> NotificationServiceInterface:
    """Get notification service instance"""
    # Import locally to avoid circular imports
    from .services.notification import NotificationService
    return NotificationService()


def get_audit_service() -> AuditServiceInterface:
    """Get audit service instance"""
    # Import locally to avoid circular imports
    from .services.audit import AuditService
    return AuditService()


# NEW: File Security Dependencies
def get_file_validator() -> FileSecurityValidator:
    """Get file security validator instance"""
    return get_file_validator(
        max_file_size=settings.max_file_size,
        allowed_mime_types=settings.allowed_file_types,
        scan_content=settings.file_scan_enabled,
        quarantine_path=None  # Could be configured via settings if needed
    )


# Test Dependencies
def get_test_hooks():
    """Get test hooks for test mode"""
    if not settings.test_mode:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Test hooks only available in test mode"
        )
    return test_hooks


def test_mode_only():
    """Dependency that only allows access in test mode"""
    if not settings.test_mode:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Endpoint not available"
        )
    return True


# Context and Correlation Dependencies
def get_correlation_id(
    x_correlation_id: Annotated[Optional[str], Header(alias="X-Correlation-ID")] = None,
    x_request_id: Annotated[Optional[str], Header(alias="X-Request-ID")] = None
) -> str:
    """Get or generate correlation ID for request tracking"""
    correlation_id = x_correlation_id or x_request_id or str(uuid.uuid4())
    
    # Set correlation context for logging
    if settings.log_correlation:
        set_correlation_context(correlation_id)
        
        # Set structlog context if available
        if STRUCTLOG_AVAILABLE and contextvars:
            contextvars.clear_contextvars()
            contextvars.bind_contextvars(correlation_id=correlation_id)
    
    return correlation_id


# FIXED: Rate Limiting Dependencies with better typing
async def check_rate_limit(
    request: Request,
    user: Optional[User] = Depends(get_current_user_optional)
) -> None:
    """Check rate limits for current request"""
    if not settings.rate_limit_enabled:
        return
    
    try:
        from .utils.rate_limiting import get_rate_limiter
        rate_limiter = get_rate_limiter()
        
        # Determine user identifier for rate limiting
        if user:
            identifier = f"user:{user.id}"
            user_role = user.role
        else:
            identifier = f"ip:{request.client.host}"
            user_role = UserRole.READONLY  # Anonymous users
        
        # Check rate limit
        result = await rate_limiter.check_rate_limit(
            identifier=identifier,
            endpoint=str(request.url.path),
            user_role=user_role
        )
        
        if not result.allowed:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Rate limit exceeded. Try again in {result.retry_after} seconds.",
                headers={
                    "Retry-After": str(result.retry_after),
                    "X-RateLimit-Remaining": str(result.remaining),
                    "X-RateLimit-Reset": str(int(result.reset_time.timestamp())) if result.reset_time else "0"
                }
            )
    except ImportError:
        # Rate limiting module not available
        logger.warning("Rate limiting requested but module not available")
        pass


# Authentication Dependencies
async def get_current_user_optional(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
    x_api_key: Annotated[Optional[str], Header(alias="X-API-Key")] = None,
    auth_service: AuthServiceInterface = Depends(get_auth_service)
) -> Optional[User]:
    """Get current user (optional - no exception if not authenticated)"""
    
    # NEW: Try SSO authentication first (if enabled)
    if settings.sso_enabled:
        try:
            sso_user = await authenticate_sso_user(request)
            if sso_user:
                logger.debug(f"User authenticated via SSO: {sso_user.email}")
                return sso_user
        except Exception as e:
            logger.debug(f"SSO authentication failed: {e}")
    
    # Try JWT token 
    if credentials:
        try:
            token = extract_bearer_token(credentials.credentials)
            if token:
                user = await auth_service.get_current_user(token)
                if user:
                    await auth_service.update_last_activity(str(user.id))
                    logger.debug(f"User authenticated via JWT: {user.email}")
                    return user
        except Exception as e:
            logger.debug(f"JWT authentication failed: {e}")
    
    # Try API key
    if x_api_key:
        try:
            if verify_api_key_format(x_api_key):
                api_key_data = await auth_service.verify_api_key(x_api_key)
                if api_key_data:
                    user = await auth_service.get_user_by_id(api_key_data["user_id"])
                    if user:
                        await auth_service.update_last_activity(str(user.id))
                        logger.debug(f"User authenticated via API key: {user.email}")
                        return user
        except Exception as e:
            logger.debug(f"API key authentication failed: {e}")
    
    return None


async def get_current_user(
    user: Optional[User] = Depends(get_current_user_optional)
) -> User:
    """Get current user (required - throws exception if not authenticated)"""
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required. Provide either Bearer token, X-API-Key header, or valid SSO headers.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user


async def get_current_active_user(
    current_user: User = Depends(get_current_user)
) -> User:
    """Get current active user (must be authenticated and active)"""
    if not current_user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is disabled"
        )
    return current_user


# Authorization Dependencies
def require_role(required_role: UserRole):
    """Create dependency that requires specific role"""
    async def _require_role(
        current_user: User = Depends(get_current_active_user)
    ) -> User:
        if current_user.role.value < required_role.value:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access denied. Required role: {required_role.value}, current role: {current_user.role.value}"
            )
        return current_user
    return _require_role


def require_admin():
    """Dependency that requires admin role"""
    return require_role(UserRole.ADMIN)


def require_manager():
    """Dependency that requires manager role or higher"""
    return require_role(UserRole.MANAGER)


# Convenience dependencies
def get_admin_user():
    """Get current user (must be admin)"""
    return require_admin()


def get_manager_user():
    """Get current user (must be manager or admin)"""
    return require_manager()


# Permission-based dependencies
def require_documents_read():
    """Require permission to read documents"""
    return get_current_active_user  # All active users can read their documents


def require_documents_write():
    """Require permission to write documents"""
    return get_current_active_user  # All active users can write documents


def require_documents_delete():
    """Require permission to delete documents"""
    return get_current_active_user  # All active users can delete their documents


def require_system_admin():
    """Require system admin access"""
    async def _require_system_admin(
        current_user: User = Depends(get_current_active_user)
    ) -> User:
        if current_user.role != UserRole.SUPER_ADMIN:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="System administrator access required"
            )
        return current_user
    return _require_system_admin


# Audit Dependencies
async def log_request_audit(
    request: Request,
    correlation_id: str = Depends(get_correlation_id),
    user: Optional[User] = Depends(get_current_user_optional),
    audit_service: AuditServiceInterface = Depends(get_audit_service)
) -> None:
    """Log request for audit purposes"""
    try:
        await audit_service.log_event(
            action="api_request",
            user_id=str(user.id) if user else None,
            details={
                "method": request.method,
                "path": str(request.url.path),
                "query_params": dict(request.query_params),
                "user_agent": request.headers.get("user-agent"),
                "endpoint": f"{request.method} {request.url.path}"
            },
            ip_address=request.client.host if request.client else None,
            correlation_id=correlation_id
        )
    except Exception as e:
        logger.warning(f"Failed to log audit event: {e}")
        # Don't raise - audit failure shouldn't break request flow