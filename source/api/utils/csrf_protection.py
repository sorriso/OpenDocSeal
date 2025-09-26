"""
Path: infrastructure/source/api/utils/csrf_protection.py
Version: 1
"""

import secrets
import logging
from typing import Optional, Set
from urllib.parse import urlparse

from fastapi import Request, HTTPException, status
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response

from ..config import get_settings

logger = logging.getLogger(__name__)
settings = get_settings()


class CSRFProtection:
    """
    CSRF Protection system adapted for API usage
    
    Provides CSRF protection for state-changing operations while
    allowing API key and programmatic access to bypass CSRF checks.
    """
    
    def __init__(
        self,
        secret_key: str,
        csrf_token_header: str = "X-CSRF-Token",
        csrf_cookie_name: str = "csrf_token",
        safe_methods: Set[str] = None,
        exempt_paths: Set[str] = None
    ):
        self.secret_key = secret_key
        self.csrf_token_header = csrf_token_header
        self.csrf_cookie_name = csrf_cookie_name
        self.safe_methods = safe_methods or {"GET", "HEAD", "OPTIONS", "TRACE"}
        self.exempt_paths = exempt_paths or {
            "/health",
            "/docs",
            "/openapi.json",
            "/api/v1/auth/login",  # Login doesn't need CSRF (creates session)
            "/api/v1/auth/register"  # Registration doesn't need CSRF
        }
        
        logger.info(f"CSRF protection initialized with header: {csrf_token_header}")
    
    def generate_csrf_token(self) -> str:
        """Generate a new CSRF token"""
        return secrets.token_urlsafe(32)
    
    def validate_csrf_token(self, request_token: str, session_token: str) -> bool:
        """
        Validate CSRF token using constant-time comparison
        
        Args:
            request_token: Token from request header/form
            session_token: Token from session/cookie
            
        Returns:
            True if tokens match
        """
        if not request_token or not session_token:
            return False
        
        # Use constant-time comparison to prevent timing attacks
        return secrets.compare_digest(request_token, session_token)
    
    def is_exempt_request(self, request: Request) -> bool:
        """
        Check if request is exempt from CSRF protection
        
        Exempt requests:
        - Safe HTTP methods (GET, HEAD, etc.)
        - API key authenticated requests
        - SSO authenticated requests
        - Explicitly exempt paths
        """
        # Safe methods don't need CSRF protection
        if request.method in self.safe_methods:
            return True
        
        # Check exempt paths
        path = request.url.path
        if path in self.exempt_paths:
            return True
        
        # Check for path prefixes
        exempt_prefixes = ["/api/test/", "/health/"]
        if any(path.startswith(prefix) for prefix in exempt_prefixes):
            return True
        
        # API key requests are exempt (programmatic access)
        if request.headers.get("X-API-Key"):
            return True
        
        # SSO requests are exempt (handled by reverse proxy)
        if settings.sso_enabled and request.headers.get(settings.sso_header_user):
            return True
        
        return False
    
    def get_csrf_token_from_request(self, request: Request) -> Optional[str]:
        """Extract CSRF token from request"""
        
        # Check header first (preferred for API)
        token = request.headers.get(self.csrf_token_header)
        if token:
            return token
        
        # Check form data for HTML forms
        if hasattr(request, 'form'):
            try:
                form_data = request.form()
                return form_data.get("csrf_token")
            except Exception:
                pass
        
        return None
    
    def get_csrf_token_from_session(self, request: Request) -> Optional[str]:
        """Get CSRF token from session/cookie"""
        
        # Check session first (if using session middleware)
        if hasattr(request, 'session') and 'csrf_token' in request.session:
            return request.session['csrf_token']
        
        # Check cookies
        return request.cookies.get(self.csrf_cookie_name)
    
    def set_csrf_token_cookie(self, response: Response, token: str):
        """Set CSRF token as secure cookie"""
        response.set_cookie(
            key=self.csrf_cookie_name,
            value=token,
            max_age=3600,  # 1 hour
            httponly=False,  # Must be accessible by JavaScript for AJAX
            secure=settings.is_production,  # HTTPS only in production
            samesite="strict"  # Strict SameSite policy
        )
    
    async def validate_request(self, request: Request) -> bool:
        """
        Validate request for CSRF protection
        
        Returns:
            True if request is valid or exempt
            
        Raises:
            HTTPException: If CSRF validation fails
        """
        # Check if request is exempt
        if self.is_exempt_request(request):
            return True
        
        # Get tokens
        request_token = self.get_csrf_token_from_request(request)
        session_token = self.get_csrf_token_from_session(request)
        
        # Validate tokens
        if not self.validate_csrf_token(request_token, session_token):
            logger.warning(
                f"CSRF validation failed for {request.method} {request.url.path}",
                extra={
                    "method": request.method,
                    "path": request.url.path,
                    "client_ip": request.client.host if request.client else None,
                    "has_request_token": bool(request_token),
                    "has_session_token": bool(session_token)
                }
            )
            
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="CSRF token validation failed. Include X-CSRF-Token header or csrf_token form field."
            )
        
        return True


class CSRFMiddleware(BaseHTTPMiddleware):
    """
    CSRF Protection Middleware
    
    Automatically validates CSRF tokens for non-exempt requests
    and provides CSRF tokens for client applications.
    """
    
    def __init__(self, app, csrf_protection: CSRFProtection):
        super().__init__(app)
        self.csrf_protection = csrf_protection
    
    async def dispatch(self, request: Request, call_next):
        """Process request with CSRF protection"""
        
        # Skip CSRF protection if disabled
        if not settings.behind_reverse_proxy:  # Only enable for web UI, not for API-only
            return await call_next(request)
        
        try:
            # Validate CSRF for non-exempt requests
            await self.csrf_protection.validate_request(request)
            
            # Process request
            response = await call_next(request)
            
            # Add CSRF token to response for new sessions
            if request.method == "GET" and not self.csrf_protection.is_exempt_request(request):
                session_token = self.csrf_protection.get_csrf_token_from_session(request)
                if not session_token:
                    # Generate new token for new sessions
                    new_token = self.csrf_protection.generate_csrf_token()
                    self.csrf_protection.set_csrf_token_cookie(response, new_token)
                    
                    # Also add to response header for SPA applications
                    response.headers["X-CSRF-Token"] = new_token
            
            return response
            
        except HTTPException:
            # Re-raise HTTP exceptions (like CSRF validation failures)
            raise
        except Exception as e:
            logger.error(f"CSRF middleware error: {e}")
            # Don't block requests on CSRF middleware errors
            return await call_next(request)


# CSRF token endpoint for applications that need to fetch tokens
async def get_csrf_token(request: Request) -> dict:
    """
    Get CSRF token for client applications
    
    This endpoint provides CSRF tokens for JavaScript applications
    that need to make state-changing requests.
    """
    csrf_protection = get_csrf_protection()
    
    # Generate new token
    token = csrf_protection.generate_csrf_token()
    
    # Store in session if available
    if hasattr(request, 'session'):
        request.session['csrf_token'] = token
    
    return {
        "csrf_token": token,
        "header_name": csrf_protection.csrf_token_header,
        "expires_in": 3600  # 1 hour
    }


# Global CSRF protection instance
_csrf_protection: Optional[CSRFProtection] = None


def get_csrf_protection() -> CSRFProtection:
    """Get global CSRF protection instance"""
    global _csrf_protection
    
    if _csrf_protection is None:
        _csrf_protection = CSRFProtection(
            secret_key=settings.secret_key,
            csrf_token_header="X-CSRF-Token",
            csrf_cookie_name="csrf_token"
        )
    
    return _csrf_protection


def create_csrf_middleware() -> CSRFMiddleware:
    """Create CSRF middleware instance"""
    csrf_protection = get_csrf_protection()
    return CSRFMiddleware(None, csrf_protection)  # app will be set by FastAPI