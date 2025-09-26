"""
Path: infrastructure/source/api/main.py
Version: 6
"""

import logging
import time
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from fastapi import FastAPI, Request, HTTPException, status, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.middleware.base import BaseHTTPMiddleware

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
from .database import connect_to_mongo, close_mongo_connection, database
from .models.base import ErrorResponse
from .routes import auth, documents, health  # FIXED: Changed from .routers to .routes
from .utils.logging import setup_logging, set_correlation_context, clear_correlation_context
from .utils.security import setup_security_headers
from .utils.rate_limiting import RateLimiter
from .utils.file_security import get_file_validator  # NEW: File security
from .utils.sso_auth import get_sso_authenticator  # NEW: SSO authentication
from .utils.security_monitoring import get_security_monitor  # NEW: Security monitoring
from .dependencies import test_mode_only, get_test_hooks
from .factories.service_factory import get_service_factory, get_test_service_factory

# Get settings
settings = get_settings()

# Setup logging with correlation support
setup_logging(
    settings.log_level, 
    settings.log_file,
    json_format=settings.is_production,
    max_file_size=10 * 1024 * 1024,
    backup_count=5,
    setup_structlog=True  # Enable structlog integration
)
logger = logging.getLogger(__name__)

# Application start time for uptime calculation
app_start_time = datetime.now(timezone.utc)


class CorrelationMiddleware(BaseHTTPMiddleware):
    """Middleware to add correlation ID to requests and logs"""
    
    async def dispatch(self, request: Request, call_next):
        """Add correlation ID to request and configure logging context"""
        # Get or generate correlation ID
        correlation_id = (
            request.headers.get("X-Correlation-ID")
            or request.headers.get("X-Request-ID")
            or str(uuid.uuid4())
        )
        
        # Set correlation context for logging
        if settings.log_correlation:
            set_correlation_context(correlation_id)
            if STRUCTLOG_AVAILABLE and contextvars:
                try:
                    contextvars.bind_contextvars(correlation_id=correlation_id)
                except Exception:
                    pass
        
        # Store in request state
        request.state.correlation_id = correlation_id
        
        # Log request start
        start_time = time.time()
        logger.debug(
            f"Request started: {request.method} {request.url.path}",
            extra={
                "correlation_id": correlation_id,
                "method": request.method,
                "path": request.url.path,
                "client_ip": request.client.host if request.client else "unknown",
                "user_agent": request.headers.get("user-agent", "unknown")
            }
        )
        
        try:
            response = await call_next(request)
            
            # Log successful request
            duration = time.time() - start_time
            logger.info(
                f"Request completed: {request.method} {request.url.path} - "
                f"Status: {response.status_code} - Duration: {duration:.3f}s",
                extra={
                    "correlation_id": correlation_id,
                    "method": request.method,
                    "path": request.url.path,
                    "status_code": response.status_code,
                    "duration": duration,
                    "client_ip": request.client.host if request.client else "unknown"
                }
            )
            
            # Add correlation ID to response headers
            response.headers["X-Correlation-ID"] = correlation_id
            return response
            
        except Exception as e:
            duration = time.time() - start_time
            logger.error(
                f"Request failed: {request.method} {request.url.path} - "
                f"Error: {str(e)} - Duration: {duration:.3f}s",
                extra={
                    "correlation_id": correlation_id,
                    "method": request.method,
                    "path": request.url.path,
                    "error": str(e),
                    "duration": duration,
                    "client_ip": request.client.host if request.client else "unknown"
                },
                exc_info=True
            )
            raise
        finally:
            # Clear correlation context after request
            if settings.log_correlation:
                clear_correlation_context()
                if STRUCTLOG_AVAILABLE and contextvars:
                    try:
                        contextvars.clear_contextvars()
                    except Exception:
                        pass


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Middleware to add security headers to responses"""
    
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        
        # Only add security headers if not behind reverse proxy or explicitly enabled
        if settings.security_headers_enabled or not settings.behind_reverse_proxy:
            setup_security_headers(response)
        
        return response


# NEW: File Security Middleware
class FileSecurityMiddleware(BaseHTTPMiddleware):
    """Middleware for preliminary file upload security validation"""
    
    def __init__(self, app):
        super().__init__(app)
        self.file_validator = get_file_validator()
        self.upload_paths = [
            "/api/v1/documents/upload",
            "/api/v1/documents/"
        ]
    
    async def dispatch(self, request: Request, call_next):
        # Check if this is a file upload request
        is_upload = (
            request.method == "POST" and
            any(request.url.path.startswith(path) for path in self.upload_paths) and
            request.headers.get("content-type", "").startswith("multipart/form-data")
        )
        
        if is_upload and settings.file_scan_enabled:
            # Log file upload attempt
            correlation_id = getattr(request.state, 'correlation_id', 'unknown')
            logger.info(
                f"File upload detected: {request.url.path}",
                extra={
                    "correlation_id": correlation_id,
                    "path": request.url.path,
                    "client_ip": request.client.host if request.client else "unknown",
                    "content_type": request.headers.get("content-type")
                }
            )
            
            # Additional security monitoring for uploads
            if settings.security_monitoring_enabled:
                try:
                    security_monitor = get_security_monitor()
                    await security_monitor.log_event(
                        event_type="file_upload_attempt",
                        severity="low",
                        source_ip=request.client.host if request.client else "unknown",
                        user_id=None,  # Will be determined later in auth flow
                        endpoint=request.url.path,
                        details={
                            "content_type": request.headers.get("content-type"),
                            "user_agent": request.headers.get("user-agent")
                        },
                        correlation_id=correlation_id
                    )
                except Exception as e:
                    logger.warning(f"Failed to log security event: {e}")
        
        response = await call_next(request)
        return response


# NEW: SSO Authentication Middleware (Optional)
class SSOMiddleware(BaseHTTPMiddleware):
    """Middleware for SSO header validation and user context setup"""
    
    def __init__(self, app):
        super().__init__(app)
        self.sso_authenticator = get_sso_authenticator() if settings.sso_enabled else None
        self.protected_paths = [
            "/api/v1/documents",
            "/api/v1/auth/profile",
            "/api/v1/auth/logout"
        ]
    
    async def dispatch(self, request: Request, call_next):
        # Only process SSO for protected paths when SSO is enabled
        if (self.sso_authenticator and settings.sso_enabled and 
            any(request.url.path.startswith(path) for path in self.protected_paths)):
            
            try:
                # Validate SSO headers early
                correlation_id = getattr(request.state, 'correlation_id', 'unknown')
                
                # Check for SSO headers presence
                has_sso_headers = bool(
                    request.headers.get(settings.sso_header_user) and
                    request.headers.get(settings.sso_header_email)
                )
                
                if has_sso_headers:
                    logger.debug(
                        f"SSO headers detected for path: {request.url.path}",
                        extra={
                            "correlation_id": correlation_id,
                            "path": request.url.path,
                            "sso_user": request.headers.get(settings.sso_header_user)
                        }
                    )
                    
                    # Store SSO context in request state for later use
                    request.state.has_sso_context = True
                else:
                    request.state.has_sso_context = False
                    
            except Exception as e:
                logger.warning(f"SSO middleware error: {e}")
                request.state.has_sso_context = False
        
        response = await call_next(request)
        return response


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Rate limiting middleware"""
    
    def __init__(self, app, rate_limiter: RateLimiter):
        super().__init__(app)
        self.rate_limiter = rate_limiter
    
    async def dispatch(self, request: Request, call_next):
        # Skip rate limiting for health checks in test mode
        if settings.test_mode and request.url.path.startswith("/health"):
            return await call_next(request)
        
        # Get client identifier
        client_ip = request.client.host if request.client else "unknown"
        
        # Use X-Forwarded-For if behind reverse proxy and trusted
        if settings.behind_reverse_proxy and settings.trust_proxy_headers:
            forwarded_for = request.headers.get("X-Forwarded-For")
            if forwarded_for:
                client_ip = forwarded_for.split(",")[0].strip()
        
        user_agent = request.headers.get("user-agent", "")
        identifier = f"ip:{client_ip}:{hash(user_agent) % 10000}"
        
        # Check rate limit
        result = await self.rate_limiter.is_allowed(identifier)
        
        if not result.allowed:
            # Log rate limit exceeded
            correlation_id = getattr(request.state, 'correlation_id', 'unknown')
            logger.warning(
                f"Rate limit exceeded: {client_ip}",
                extra={
                    "correlation_id": correlation_id,
                    "client_ip": client_ip,
                    "path": request.url.path,
                    "remaining": result.remaining,
                    "reset_time": result.reset_time
                }
            )
            
            # Security monitoring for rate limit violations
            if settings.security_monitoring_enabled:
                try:
                    security_monitor = get_security_monitor()
                    await security_monitor.log_event(
                        event_type="rate_limit_exceeded",
                        severity="medium",
                        source_ip=client_ip,
                        user_id=None,
                        endpoint=request.url.path,
                        details={
                            "remaining": result.remaining,
                            "reset_time": result.reset_time.isoformat() if result.reset_time else None,
                            "user_agent": user_agent
                        },
                        correlation_id=correlation_id
                    )
                except Exception as e:
                    logger.warning(f"Failed to log security event: {e}")
            
            # Return rate limit error
            return JSONResponse(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                content={
                    "error": "RATE_LIMIT_EXCEEDED",
                    "detail": f"Too many requests. Try again in {result.retry_after} seconds.",
                    "retry_after": result.retry_after
                },
                headers={
                    "Retry-After": str(result.retry_after),
                    "X-RateLimit-Remaining": str(result.remaining),
                    "X-RateLimit-Reset": str(int(result.reset_time.timestamp())) if result.reset_time else "0"
                }
            )
        
        return await call_next(request)


# Application lifecycle
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan management"""
    # Startup
    logger.info(f"🚀 Starting OpenDocSeal API v{settings.app_version}")
    logger.info(f"Environment: {settings.environment}")
    logger.info(f"Debug mode: {settings.debug}")
    logger.info(f"Test mode: {settings.test_mode}")
    logger.info(f"SSO enabled: {settings.sso_enabled}")
    logger.info(f"Behind reverse proxy: {settings.behind_reverse_proxy}")
    logger.info(f"Security monitoring: {settings.security_monitoring_enabled}")
    
    try:
        # Connect to database
        await connect_to_mongo()
        logger.info("📊 Database connected successfully")
        
        # Initialize services
        if settings.test_mode:
            factory = get_test_service_factory()
            logger.info("🧪 Test service factory initialized")
        else:
            factory = get_service_factory()
            logger.info("🏭 Production service factory initialized")
        
        # Test service connectivity
        auth_service = factory.create_auth_service()
        blockchain_service = factory.create_blockchain_service()
        storage_service = factory.create_storage_service()
        document_service = factory.create_document_service()
        
        logger.info("✅ All services initialized successfully")
        
        # Initialize security components
        if settings.file_scan_enabled:
            file_validator = get_file_validator()
            logger.info("🛡️ File security validator initialized")
        
        if settings.sso_enabled:
            sso_authenticator = get_sso_authenticator()
            logger.info("🔐 SSO authenticator initialized")
        
        if settings.security_monitoring_enabled:
            security_monitor = get_security_monitor()
            logger.info("👁️ Security monitoring initialized")
        
        logger.info("🎉 OpenDocSeal API startup complete!")
        
        yield
        
    except Exception as e:
        logger.error(f"❌ Failed to start OpenDocSeal API: {e}")
        raise
    
    # Shutdown
    logger.info("🛑 Shutting down OpenDocSeal API...")
    
    try:
        # Close database connection
        await close_mongo_connection()
        logger.info("Database disconnected successfully")
    except Exception as e:
        logger.error(f"Error during database disconnect: {e}")
    
    logger.info("👋 OpenDocSeal API shutdown complete")


# Create FastAPI application
app = FastAPI(
    title="OpenDocSeal API",
    description="Complete API for document notarization with blockchain timestamping",
    version=settings.app_version,
    debug=settings.debug,
    lifespan=lifespan,
    openapi_url="/openapi.json" if settings.enable_docs else None,
    docs_url="/docs" if settings.enable_docs else None,
    redoc_url="/redoc" if settings.enable_docs else None
)

# Add test control routes only in test mode
if settings.test_mode:
    from .routes import test_control
    app.include_router(test_control.router, prefix="/api/test", tags=["test-control"])
    logger.info("🧪 Test control routes enabled")

# CORS Configuration (only if not behind reverse proxy or explicitly enabled)
if settings.cors_enabled or (settings.debug and not settings.behind_reverse_proxy):
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"] if settings.debug else settings.cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    logger.info("🌐 CORS middleware enabled")

# Trusted Host Middleware (only in production)
if settings.is_production and not settings.behind_reverse_proxy:
    app.add_middleware(
        TrustedHostMiddleware,
        allowed_hosts=settings.allowed_hosts
    )
    logger.info("🛡️ Trusted host middleware enabled")

# Rate Limiting Middleware
if settings.rate_limit_enabled:
    from .utils.rate_limiting import create_rate_limiter
    rate_limiter = create_rate_limiter(
        default_requests=settings.rate_limit_requests,
        default_window=settings.rate_limit_window
    )
    app.add_middleware(RateLimitMiddleware, rate_limiter=rate_limiter)
    logger.info("⚡ Rate limiting middleware enabled")

# NEW: Add security middlewares
if settings.file_scan_enabled:
    app.add_middleware(FileSecurityMiddleware)
    logger.info("📁 File security middleware enabled")

if settings.sso_enabled:
    app.add_middleware(SSOMiddleware)
    logger.info("🔐 SSO middleware enabled")

# Add custom middlewares (order matters - last added = first executed)
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(CorrelationMiddleware)

logger.info("🔧 All middlewares configured")

# Include routers
app.include_router(health.router, prefix="/health", tags=["health"])
app.include_router(auth.router, prefix="/api/v1/auth", tags=["authentication"])
app.include_router(documents.router, prefix="/api/v1/documents", tags=["documents"])

logger.info("🛣️ All routes configured")


# Exception Handlers
@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    """Handle HTTP exceptions with correlation"""
    correlation_id = getattr(request.state, 'correlation_id', 'unknown')
    
    logger.warning(
        f"HTTP {exc.status_code}: {exc.detail}",
        extra={
            "correlation_id": correlation_id,
            "status_code": exc.status_code,
            "path": request.url.path,
            "method": request.method
        }
    )
    
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": "HTTP_EXCEPTION",
            "detail": exc.detail,
            "correlation_id": correlation_id
        }
    )


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    """Handle request validation errors"""
    correlation_id = getattr(request.state, 'correlation_id', 'unknown')
    
    logger.warning(
        f"Validation error: {exc.errors()}",
        extra={
            "correlation_id": correlation_id,
            "path": request.url.path,
            "method": request.method,
            "errors": exc.errors()
        }
    )
    
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={
            "error": "VALIDATION_ERROR",
            "detail": "Request validation failed",
            "errors": exc.errors(),
            "correlation_id": correlation_id
        }
    )


@app.exception_handler(500)
async def internal_server_error_handler(request: Request, exc: Exception):
    """Handle internal server errors"""
    correlation_id = getattr(request.state, 'correlation_id', 'unknown')
    
    logger.error(
        f"Internal server error: {str(exc)}",
        extra={
            "correlation_id": correlation_id,
            "path": request.url.path,
            "method": request.method
        },
        exc_info=True
    )
    
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "error": "INTERNAL_SERVER_ERROR",
            "detail": "An internal error occurred" if settings.is_production else str(exc),
            "correlation_id": correlation_id
        }
    )


# Root endpoint
@app.get("/", include_in_schema=False)
async def root():
    """Root endpoint"""
    return {
        "service": "OpenDocSeal API",
        "version": settings.app_version,
        "status": "healthy",
        "environment": settings.environment,
        "docs_url": "/docs" if settings.enable_docs else None,
        "health_url": "/health"
    }


# Version endpoint
@app.get("/version", tags=["system"])
async def get_version():
    """Get API version information"""
    uptime = datetime.now(timezone.utc) - app_start_time
    
    return {
        "version": settings.app_version,
        "environment": settings.environment,
        "debug": settings.debug,
        "test_mode": settings.test_mode,
        "sso_enabled": settings.sso_enabled,
        "security_features": {
            "file_scanning": settings.file_scan_enabled,
            "security_monitoring": settings.security_monitoring_enabled,
            "rate_limiting": settings.rate_limit_enabled,
            "behind_reverse_proxy": settings.behind_reverse_proxy
        },
        "uptime_seconds": int(uptime.total_seconds()),
        "started_at": app_start_time.isoformat()
    }