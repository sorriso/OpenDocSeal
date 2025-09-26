"""
Path: infrastructure/source/api/routes/auth.py
Version: 6 - INTERFACE SIGNATURE FIXES
"""

import logging
from datetime import datetime, timezone
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, status, Request, Response
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

from ..models.auth import (
    UserCreate, UserUpdate, UserResponse, LoginRequest, TokenResponse,
    RefreshTokenRequest, PasswordChangeRequest, PasswordResetRequest,
    PasswordResetConfirm, EmailVerificationRequest, EmailVerificationConfirm,
    APIKeyCreate, APIKeyResponse
)
from ..models.base import ResponseModel, ErrorResponse
from ..services.interfaces import AuthServiceInterface
from ..dependencies import (
    get_auth_service, get_current_user, get_current_active_user,
    get_admin_user, get_correlation_id
)
from ..database import log_audit_event
from ..config import get_settings
from ..utils.sso_auth import authenticate_sso_user  # NEW: SSO authentication
from ..utils.jwt_blacklist import blacklist_token  # NEW: JWT blacklist

logger = logging.getLogger(__name__)
settings = get_settings()
security = HTTPBearer()

router = APIRouter()


# NEW: SSO Authentication Status Endpoint
@router.get(
    "/sso/status",
    response_model=ResponseModel,
    summary="Get SSO status",
    description="Get SSO authentication status and configuration",
    responses={
        200: {"description": "SSO status retrieved successfully"}
    }
)
async def get_sso_status(
    request: Request,
    correlation_id: str = Depends(get_correlation_id)
) -> ResponseModel:
    """Get SSO authentication status and configuration"""
    
    sso_status = {
        "enabled": settings.sso_enabled,
        "behind_proxy": settings.behind_reverse_proxy,
        "headers_required": [
            "X-Remote-User",
            "X-Remote-Name", 
            "X-Remote-Email"
        ] if settings.sso_enabled else []
    }
    
    # Check if SSO headers are present
    if settings.sso_enabled:
        sso_headers = {
            "user": request.headers.get("X-Remote-User"),
            "name": request.headers.get("X-Remote-Name"),
            "email": request.headers.get("X-Remote-Email")
        }
        sso_status["headers_present"] = all(v is not None for v in sso_headers.values())
        
        # Don't expose actual values for security
        sso_status["headers_detected"] = {k: bool(v) for k, v in sso_headers.items()}
    
    return ResponseModel(
        success=True,
        message="SSO status retrieved",
        data=sso_status
    )


# User registration
@router.post(
    "/register",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register new user",
    description="Create a new user account with email verification",
    responses={
        201: {"description": "User created successfully"},
        400: {"description": "User already exists or validation failed"}
    }
)
async def register_user(
    user_data: UserCreate,
    request: Request,
    auth_service: AuthServiceInterface = Depends(get_auth_service),
    correlation_id: str = Depends(get_correlation_id)
) -> UserResponse:
    """Register a new user"""
    
    try:
        # Create user through auth service
        new_user = await auth_service.create_user(user_data)
        
        # Log registration event
        await log_audit_event(
            action="user_registration",
            user_id=str(new_user.id),
            details={
                "email": new_user.email,
                "name": new_user.name,
                "role": new_user.role.value
            },
            ip_address=request.client.host if request.client else None,
            correlation_id=correlation_id
        )
        
        logger.info(
            f"User registered successfully: {new_user.email}",
            extra={
                "correlation_id": correlation_id,
                "user_id": str(new_user.id)
            }
        )
        
        return UserResponse.from_user(new_user)
        
    except ValueError as e:
        logger.warning(
            f"User registration failed: {e}",
            extra={"correlation_id": correlation_id}
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except Exception as e:
        logger.error(
            f"User registration error: {e}",
            extra={"correlation_id": correlation_id}
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Registration failed"
        )


# User login
@router.post(
    "/login",
    response_model=TokenResponse,
    summary="User login",
    description="Authenticate user with email and password, returns JWT tokens",
    responses={
        200: {"description": "Login successful, tokens returned"},
        401: {"description": "Invalid credentials or account disabled"},
        429: {"description": "Too many login attempts"}
    }
)
async def login_user(
    login_data: LoginRequest,
    request: Request,
    auth_service: AuthServiceInterface = Depends(get_auth_service),
    correlation_id: str = Depends(get_correlation_id)
) -> TokenResponse:
    """Authenticate user and return JWT tokens"""
    
    try:
        # Skip login in SSO mode - user should already be authenticated
        if settings.sso_enabled:
            logger.warning(
                "Login endpoint called while SSO is enabled",
                extra={
                    "correlation_id": correlation_id,
                    "email": login_data.email,
                    "client_ip": request.client.host if request.client else "unknown"
                }
            )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Login not available in SSO mode. Use SSO authentication."
            )
        
        # FIXED: Pass LoginRequest directly to match interface signature
        tokens = await auth_service.authenticate_user(
            login_request=login_data,
            client_ip=request.client.host
        )
        
        if not tokens:
            logger.warning(
                f"Authentication failed for: {login_data.email}",
                extra={
                    "correlation_id": correlation_id,
                    "client_ip": request.client.host if request.client else "unknown"
                }
            )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid credentials"
            )
        
        # Log successful login
        await log_audit_event(
            action="user_login",
            user_id=tokens.user.get("id") if hasattr(tokens, 'user') and tokens.user else None,
            details={
                "email": login_data.email,
                "client_ip": request.client.host if request.client else None,
                "user_agent": request.headers.get("user-agent"),
                "sso_mode": settings.sso_enabled
            },
            ip_address=request.client.host,
            correlation_id=correlation_id
        )
        
        logger.info(
            f"User authenticated successfully: {login_data.email}",
            extra={
                "correlation_id": correlation_id,
                "user_id": tokens.user.get("id") if hasattr(tokens, 'user') and tokens.user else None
            }
        )
        
        return tokens
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(
            f"Login error: {e}",
            extra={
                "correlation_id": correlation_id,
                "email": login_data.email
            }
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Login failed"
        )


# Token refresh
@router.post(
    "/refresh",
    response_model=TokenResponse,
    summary="Refresh access token",
    description="Use refresh token to obtain new access token",
    responses={
        200: {"description": "Token refreshed successfully"},
        401: {"description": "Invalid or expired refresh token"}
    }
)
async def refresh_token(
    refresh_data: RefreshTokenRequest,
    request: Request,
    auth_service: AuthServiceInterface = Depends(get_auth_service),
    correlation_id: str = Depends(get_correlation_id)
) -> TokenResponse:
    """Refresh access token using refresh token"""
    
    # Skip refresh in SSO mode
    if settings.sso_enabled:
        logger.info(
            "Token refresh skipped in SSO mode",
            extra={
                "correlation_id": correlation_id,
                "client_ip": request.client.host if request.client else "unknown"
            }
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Token refresh not available in SSO mode",
        )
    
    try:
        # FIXED: Use the correct service method signature
        new_tokens = await auth_service.refresh_token(
            refresh_data.refresh_token
        )
        
        if not new_tokens:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired refresh token"
            )
        
        # Log token refresh
        await log_audit_event(
            action="token_refreshed",
            user_id=new_tokens.user.get("id") if hasattr(new_tokens, 'user') and new_tokens.user else None,
            details={
                "client_ip": request.client.host if request.client else None,
                "user_agent": request.headers.get("user-agent"),
                "sso_mode": settings.sso_enabled
            },
            ip_address=request.client.host,
            correlation_id=correlation_id
        )
        
        logger.info(
            f"Token refreshed for user: {new_tokens.user.get('id') if hasattr(new_tokens, 'user') and new_tokens.user else 'unknown'}",
            extra={
                "correlation_id": correlation_id,
                "user_id": new_tokens.user.get("id") if hasattr(new_tokens, 'user') and new_tokens.user else None
            }
        )
        
        return new_tokens
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(
            f"Token refresh error: {e}",
            extra={"correlation_id": correlation_id}
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Token refresh failed"
        )


# NEW: Enhanced Logout with JWT Blacklist
@router.post(
    "/logout",
    response_model=ResponseModel,
    summary="User logout",
    description="Logout user and blacklist current token",
    responses={
        200: {"description": "Logout successful"},
        401: {"description": "Authentication required"}
    }
)
async def logout_user(
    request: Request,
    credentials: HTTPAuthorizationCredentials = Depends(security),
    current_user = Depends(get_current_active_user),
    auth_service: AuthServiceInterface = Depends(get_auth_service),
    correlation_id: str = Depends(get_correlation_id)
) -> ResponseModel:
    """Logout user and blacklist token"""
    
    try:
        # Extract token
        token = credentials.credentials if credentials else None
        
        # Blacklist the current token if JWT blacklist is enabled
        if settings.jwt_blacklist_enabled and token:
            try:
                # Verify token to get expiry
                from ..utils.security import verify_token
                payload = verify_token(token)
                
                if payload and 'exp' in payload and 'jti' in payload:
                    from datetime import datetime, timezone
                    expiry = datetime.fromtimestamp(payload['exp'], tz=timezone.utc)
                    
                    # Blacklist the token
                    await blacklist_token(payload['jti'], expiry)
                    
                    logger.info(
                        f"Token blacklisted on logout: {payload['jti'][:8]}...",
                        extra={
                            "correlation_id": correlation_id,
                            "user_id": str(current_user.id)
                        }
                    )
                    
            except Exception as e:
                logger.warning(f"Failed to blacklist token on logout: {e}")
        
        # Log logout event
        await log_audit_event(
            action="user_logout",
            user_id=str(current_user.id),
            details={
                "email": current_user.email,
                "client_ip": request.client.host if request.client else None,
                "token_blacklisted": settings.jwt_blacklist_enabled and token is not None
            },
            ip_address=request.client.host,
            correlation_id=correlation_id
        )
        
        logger.info(
            f"User logged out: {current_user.email}",
            extra={
                "correlation_id": correlation_id,
                "user_id": str(current_user.id)
            }
        )
        
        return ResponseModel(
            success=True,
            message="Logout successful"
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(
            f"Logout error: {e}",
            extra={
                "correlation_id": correlation_id,
                "user_id": str(current_user.id) if current_user else "unknown"
            }
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Logout failed"
        )


# User profile endpoints
@router.get(
    "/profile",
    response_model=UserResponse,
    summary="Get user profile",
    description="Get current user profile information",
    responses={
        200: {"description": "Profile retrieved successfully"},
        401: {"description": "Authentication required"}
    }
)
async def get_user_profile(
    current_user = Depends(get_current_active_user),
    correlation_id: str = Depends(get_correlation_id)
) -> UserResponse:
    """Get current user profile"""
    
    logger.debug(
        f"Profile requested for user: {current_user.email}",
        extra={
            "correlation_id": correlation_id,
            "user_id": str(current_user.id)
        }
    )
    
    return UserResponse.from_user(current_user)


@router.put(
    "/profile",
    response_model=UserResponse,
    summary="Update user profile",
    description="Update current user profile information",
    responses={
        200: {"description": "Profile updated successfully"},
        400: {"description": "Validation error"},
        401: {"description": "Authentication required"}
    }
)
async def update_user_profile(
    user_update: UserUpdate,
    request: Request,
    current_user = Depends(get_current_active_user),
    auth_service: AuthServiceInterface = Depends(get_auth_service),
    correlation_id: str = Depends(get_correlation_id)
) -> UserResponse:
    """Update current user profile"""
    
    try:
        updated_user = await auth_service.update_user(
            str(current_user.id),
            user_update
        )
        
        # Log profile update
        await log_audit_event(
            action="profile_updated",
            user_id=str(current_user.id),
            details={
                "email": current_user.email,
                "fields_updated": list(user_update.model_dump(exclude_unset=True).keys())
            },
            ip_address=request.client.host,
            correlation_id=correlation_id
        )
        
        logger.info(
            f"Profile updated for user: {current_user.email}",
            extra={
                "correlation_id": correlation_id,
                "user_id": str(current_user.id)
            }
        )
        
        return UserResponse.from_user(updated_user)
        
    except Exception as e:
        logger.error(
            f"Profile update error: {e}",
            extra={
                "correlation_id": correlation_id,
                "user_id": str(current_user.id)
            }
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Profile update failed"
        )


# Password change
@router.post(
    "/change-password",
    response_model=ResponseModel,
    summary="Change password",
    description="Change user password with current password verification",
    responses={
        200: {"description": "Password changed successfully"},
        400: {"description": "Invalid current password or validation failed"},
        401: {"description": "Authentication required"}
    }
)
async def change_password(
    password_change: PasswordChangeRequest,
    request: Request,
    current_user = Depends(get_current_active_user),
    auth_service: AuthServiceInterface = Depends(get_auth_service),
    correlation_id: str = Depends(get_correlation_id)
) -> ResponseModel:
    """Change user password"""
    
    try:
        success = await auth_service.change_password(
            str(current_user.id),
            password_change
        )
        
        if not success:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Password change failed"
            )
        
        # Log password change
        await log_audit_event(
            action="password_changed",
            user_id=str(current_user.id),
            details={
                "email": current_user.email
            },
            ip_address=request.client.host,
            correlation_id=correlation_id
        )
        
        logger.info(
            f"Password changed for user: {current_user.email}",
            extra={
                "correlation_id": correlation_id,
                "user_id": str(current_user.id)
            }
        )
        
        return ResponseModel(
            success=True,
            message="Password changed successfully"
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(
            f"Password change error: {e}",
            extra={
                "correlation_id": correlation_id,
                "user_id": str(current_user.id)
            }
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Password change failed"
        )


# API Key management (Admin only)
@router.post(
    "/api-keys",
    response_model=APIKeyResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create API key",
    description="Create new API key for current user",
    responses={
        201: {"description": "API key created successfully"},
        401: {"description": "Authentication required"},
        403: {"description": "Admin access required"}
    }
)
async def create_api_key(
    api_key_data: APIKeyCreate,
    request: Request,
    current_user = Depends(get_admin_user),
    auth_service: AuthServiceInterface = Depends(get_auth_service),
    correlation_id: str = Depends(get_correlation_id)
) -> APIKeyResponse:
    """Create new API key"""
    
    try:
        api_key = await auth_service.create_api_key(
            str(current_user.id),
            api_key_data
        )
        
        # Log API key creation
        await log_audit_event(
            action="api_key_created",
            user_id=str(current_user.id),
            details={
                "email": current_user.email,
                "key_name": api_key_data.name
            },
            ip_address=request.client.host,
            correlation_id=correlation_id
        )
        
        logger.info(
            f"API key created for user: {current_user.email}",
            extra={
                "correlation_id": correlation_id,
                "user_id": str(current_user.id),
                "key_name": api_key_data.name
            }
        )
        
        return api_key
        
    except Exception as e:
        logger.error(
            f"API key creation error: {e}",
            extra={
                "correlation_id": correlation_id,
                "user_id": str(current_user.id)
            }
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="API key creation failed"
        )


# User management endpoints (Admin only)
@router.get(
    "/users",
    response_model=List[UserResponse],
    summary="List users",
    description="Get list of all users (admin only)",
    responses={
        200: {"description": "Users retrieved successfully"},
        401: {"description": "Authentication required"},
        403: {"description": "Admin access required"}
    }
)
async def list_users(
    current_user = Depends(get_admin_user),
    auth_service: AuthServiceInterface = Depends(get_auth_service),
    correlation_id: str = Depends(get_correlation_id)
) -> List[UserResponse]:
    """Get list of all users (admin only)"""
    
    try:
        users = await auth_service.get_all_users()
        
        logger.info(
            f"User list requested by admin: {current_user.email}",
            extra={
                "correlation_id": correlation_id,
                "admin_user_id": str(current_user.id),
                "users_count": len(users)
            }
        )
        
        return [UserResponse.from_user(user) for user in users]
        
    except Exception as e:
        logger.error(
            f"List users error: {e}",
            extra={
                "correlation_id": correlation_id,
                "admin_user_id": str(current_user.id)
            }
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve users"
        )