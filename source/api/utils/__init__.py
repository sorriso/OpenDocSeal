"""
Path: infrastructure/source/api/utils/__init__.py
Version: 2
"""

# Core utilities
from logging import (
    setup_logging,
    get_logger,
    set_correlation_context,
    clear_correlation_context,
    log_with_context,
    CorrelationFilter
)

from security import (
    hash_password,
    verify_password,
    create_access_token,
    create_refresh_token,
    verify_token,
    extract_bearer_token,
    constant_time_compare,
    generate_csrf_token,
    hash_file_content,
    secure_filename,
    detect_malicious_input,
    setup_security_headers,
    validate_url,
    generate_document_reference,
    check_rate_limit,
    generate_secure_filename_with_hash
)

from rate_limiting import (
    RateLimiter,
    RateLimitStrategy,
    RateLimitResult,
    create_rate_limiter,
    SlidingWindowRateLimiter,
    TokenBucketRateLimiter,
    FixedWindowRateLimiter
)

# NEW: File security utilities
from file_security import (
    FileSecurityValidator,
    get_file_validator,
    validate_file_upload,
    DANGEROUS_EXTENSIONS,
    MAGIC_SIGNATURES,
    SUSPICIOUS_NAME_PATTERNS,
    MALWARE_PATTERNS
)

# NEW: SSO authentication utilities
from sso_auth import (
    SSOAuthenticator,
    get_sso_authenticator,
    authenticate_sso_user
)

# NEW: JWT blacklist utilities
from jwt_blacklist import (
    TokenBlacklist,
    get_token_blacklist,
    blacklist_token,
    is_token_blacklisted
)

# NEW: Security monitoring utilities
from security_monitoring import (
    SecurityMonitor,
    SecurityEvent,
    ThreatIndicator,
    get_security_monitor
)

__all__ = [
    # Core logging
    "setup_logging",
    "get_logger", 
    "set_correlation_context",
    "clear_correlation_context",
    "log_with_context",
    "CorrelationFilter",
    
    # Core security
    "hash_password",
    "verify_password",
    "create_access_token",
    "create_refresh_token",
    "verify_token",
    "extract_bearer_token",
    "constant_time_compare",
    "generate_csrf_token",
    "hash_file_content",
    "secure_filename",
    "detect_malicious_input",
    "setup_security_headers",
    "validate_url",
    "generate_document_reference",
    "check_rate_limit",
    "generate_secure_filename_with_hash",
    
    # Rate limiting
    "RateLimiter",
    "RateLimitStrategy",
    "RateLimitResult", 
    "create_rate_limiter",
    "SlidingWindowRateLimiter",
    "TokenBucketRateLimiter",
    "FixedWindowRateLimiter",
    
    # File security (NEW)
    "FileSecurityValidator",
    "get_file_validator",
    "validate_file_upload",
    "DANGEROUS_EXTENSIONS",
    "MAGIC_SIGNATURES",
    "SUSPICIOUS_NAME_PATTERNS",
    "MALWARE_PATTERNS",
    
    # SSO authentication (NEW)
    "SSOAuthenticator",
    "get_sso_authenticator",
    "authenticate_sso_user",
    
    # JWT blacklist (NEW)
    "TokenBlacklist",
    "get_token_blacklist",
    "blacklist_token",
    "is_token_blacklisted",
    
    # Security monitoring (NEW)
    "SecurityMonitor",
    "SecurityEvent",
    "ThreatIndicator",
    "get_security_monitor"
]

# Package metadata
__version__ = "2.0.0"
__description__ = "Utility modules for OpenDocSeal API - Enhanced security, logging, and monitoring"