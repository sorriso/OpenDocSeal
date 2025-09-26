"""
Path: infrastructure/source/api/utils/security.py
Version: 2
"""

import hashlib
import hmac
import secrets
import re
import time
import urllib.parse
from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, Any, List, Union
import logging

import bcrypt
import jwt
# FIXED: Updated PyJWT imports for 2.10.1+ compatibility
from jwt.exceptions import PyJWTError, InvalidTokenError, ExpiredSignatureError, InvalidSignatureError
from fastapi import FastAPI, Request, HTTPException, status
from fastapi.security import HTTPBearer
from fastapi.responses import Response
from email_validator import validate_email as email_validator_validate, EmailNotValidError

logger = logging.getLogger(__name__)

# Security constants
MIN_PASSWORD_LENGTH = 8
MAX_PASSWORD_LENGTH = 128
BCRYPT_ROUNDS = 12
TOKEN_BYTE_LENGTH = 32
API_KEY_PREFIX = "odseal_"

# Common password patterns to reject
COMMON_PASSWORDS = {
    "password", "123456", "123456789", "qwerty", "abc123", "password123",
    "admin", "letmein", "welcome", "monkey", "dragon", "master"
}

# XSS patterns
XSS_PATTERNS = [
    r'<script[^>]*>.*?</script>',
    r'javascript:',
    r'vbscript:',
    r'onload=',
    r'onerror=',
    r'onclick=',
    r'onmouseover=',
    r'<iframe[^>]*>.*?</iframe>',
    r'<embed[^>]*>',
    r'<object[^>]*>',
]

# SQL injection patterns
SQL_INJECTION_PATTERNS = [
    r"('|(\\'))+.*(or|union|select|insert|update|delete|drop|create|alter)",
    r"\\x(27|22|23|3d|3c|3e|2f|5c)",
    r"(union|select|insert|update|delete|drop|create|alter).+(from|where|into)",
    r"(exec|execute|sp_|xp_)",
]


def generate_secure_token(length: int = TOKEN_BYTE_LENGTH) -> str:
    """
    Generate cryptographically secure random token
    
    Args:
        length: Token length in bytes
        
    Returns:
        URL-safe base64 encoded token
    """
    return secrets.token_urlsafe(length)


def generate_api_key() -> str:
    """
    Generate secure API key with prefix
    
    Returns:
        Formatted API key
    """
    token = secrets.token_urlsafe(32)
    return f"{API_KEY_PREFIX}{token}"


def hash_password(password: str) -> str:
    """
    Hash password using bcrypt with updated API
    
    Args:
        password: Plain text password
        
    Returns:
        Hashed password
    """
    if not password:
        raise ValueError("Password cannot be empty")
    
    if len(password) > MAX_PASSWORD_LENGTH:
        raise ValueError(f"Password cannot exceed {MAX_PASSWORD_LENGTH} characters")
    
    # FIXED: Updated bcrypt API for version 4.3.0+ compatibility
    salt = bcrypt.gensalt(rounds=BCRYPT_ROUNDS, prefix=b"2b")
    password_hash = bcrypt.hashpw(password.encode('utf-8'), salt)
    return password_hash.decode('utf-8')


def verify_password(password: str, hashed: str) -> bool:
    """
    Verify password against hash with enhanced error handling
    
    Args:
        password: Plain text password
        hashed: Hashed password
        
    Returns:
        True if password matches
    """
    if not password or not hashed:
        return False
    
    try:
        return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))
    except (ValueError, TypeError, UnicodeError) as e:
        logger.warning(f"Password verification failed: {e}")
        return False
    except Exception as e:
        logger.error(f"Unexpected error during password verification: {e}")
        return False


def validate_password_strength(password: str) -> Dict[str, Any]:
    """
    Validate password strength with detailed feedback
    
    Args:
        password: Password to validate
        
    Returns:
        Validation result with score and feedback
    """
    if not password:
        return {
            "valid": False,
            "score": 0,
            "issues": ["Password cannot be empty"],
            "strength": "invalid"
        }
    
    issues = []
    score = 0
    
    # Length check
    if len(password) < MIN_PASSWORD_LENGTH:
        issues.append(f"Password must be at least {MIN_PASSWORD_LENGTH} characters long")
    elif len(password) >= 12:
        score += 2
    else:
        score += 1
    
    if len(password) > MAX_PASSWORD_LENGTH:
        issues.append(f"Password must not exceed {MAX_PASSWORD_LENGTH} characters")
        return {
            "valid": False,
            "score": 0,
            "issues": issues,
            "strength": "invalid"
        }
    
    # Character variety checks
    has_lower = bool(re.search(r'[a-z]', password))
    has_upper = bool(re.search(r'[A-Z]', password))
    has_digit = bool(re.search(r'\d', password))
    has_special = bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', password))
    
    if has_lower:
        score += 1
    else:
        issues.append("Password must contain at least one lowercase letter")
    
    if has_upper:
        score += 1
    else:
        issues.append("Password must contain at least one uppercase letter")
    
    if has_digit:
        score += 1
    else:
        issues.append("Password must contain at least one digit")
    
    if has_special:
        score += 2
    else:
        issues.append("Password must contain at least one special character")
    
    # Common password check
    if password.lower() in COMMON_PASSWORDS:
        issues.append("Password is too common")
        score = max(0, score - 3)
    
    # Repetition check
    if len(set(password)) < len(password) * 0.6:
        issues.append("Password has too many repeated characters")
        score = max(0, score - 1)
    
    # Determine strength
    if len(issues) > 0:
        strength = "invalid"
        valid = False
    elif score >= 7:
        strength = "strong"
        valid = True
    elif score >= 5:
        strength = "medium"
        valid = True
    else:
        strength = "weak"
        valid = True
    
    return {
        "valid": valid,
        "score": score,
        "issues": issues,
        "strength": strength,
        "has_lower": has_lower,
        "has_upper": has_upper,
        "has_digit": has_digit,
        "has_special": has_special
    }


def sanitize_input(input_string: str, max_length: int = 1000) -> str:
    """
    Sanitize user input to prevent XSS and injection attacks
    
    Args:
        input_string: Input to sanitize
        max_length: Maximum allowed length
        
    Returns:
        Sanitized input
    """
    if not isinstance(input_string, str):
        return ""
    
    # Truncate to max length
    sanitized = input_string[:max_length]
    
    # Remove null bytes
    sanitized = sanitized.replace('\x00', '')
    
    # Basic HTML encoding for XSS prevention
    html_escape_table = {
        "&": "&amp;",
        '"': "&quot;",
        "'": "&#x27;",
        ">": "&gt;",
        "<": "&lt;",
    }
    
    for char, escaped in html_escape_table.items():
        sanitized = sanitized.replace(char, escaped)
    
    return sanitized.strip()


def validate_email(email: str) -> Dict[str, Any]:
    """
    Validate email address with enhanced checks
    
    Args:
        email: Email address to validate
        
    Returns:
        Validation result
    """
    try:
        # Use email-validator for basic validation
        validated_email = email_validator_validate(email)
        email_address = validated_email.email.lower()
        
        # Additional security checks
        if len(email_address) > 254:  # RFC 5321 limit
            return {"valid": False, "error": "Email address too long"}
        
        # Check for suspicious patterns
        suspicious_patterns = [
            r'\.{2,}',  # Multiple consecutive dots
            r'^\.|\.$',  # Starting or ending with dot
            r'[<>"\']',  # Potentially dangerous characters
        ]
        
        for pattern in suspicious_patterns:
            if re.search(pattern, email_address):
                return {"valid": False, "error": "Invalid email format"}
        
        return {
            "valid": True,
            "email": email_address,
            "domain": validated_email.domain,
            "local": validated_email.local
        }
        
    except EmailNotValidError as e:
        return {"valid": False, "error": str(e)}
    except Exception as e:
        logger.error(f"Email validation error: {e}")
        return {"valid": False, "error": "Email validation failed"}


def validate_url(url: str, allowed_schemes: List[str] = None) -> Dict[str, Any]:
    """
    Validate URL with security checks
    
    Args:
        url: URL to validate
        allowed_schemes: Allowed URL schemes
        
    Returns:
        Validation result
    """
    if not url:
        return {"valid": False, "error": "URL cannot be empty"}
    
    if allowed_schemes is None:
        allowed_schemes = ["http", "https"]
    
    try:
        parsed = urllib.parse.urlparse(url)
        
        if not parsed.scheme:
            return {"valid": False, "error": "URL must include scheme (http/https)"}
        
        if parsed.scheme.lower() not in allowed_schemes:
            return {"valid": False, "error": f"Scheme not allowed: {parsed.scheme}"}
        
        if not parsed.netloc:
            return {"valid": False, "error": "URL must include domain"}
        
        # Check for suspicious patterns
        if any(char in url for char in ['<', '>', '"', "'"]):
            return {"valid": False, "error": "URL contains invalid characters"}
        
        # Check for localhost/private IPs in production
        if parsed.hostname:
            if parsed.hostname.lower() in ['localhost', '127.0.0.1', '::1']:
                return {"valid": False, "error": "Localhost URLs not allowed"}
        
        return {
            "valid": True,
            "scheme": parsed.scheme,
            "domain": parsed.hostname,
            "port": parsed.port,
            "path": parsed.path
        }
        
    except Exception as e:
        return {"valid": False, "error": str(e)}


def setup_security_headers(app: FastAPI):
    """
    Setup security headers middleware with updated CSP
    
    Args:
        app: FastAPI application instance
    """
    @app.middleware("http")
    async def security_headers_middleware(request: Request, call_next):
        """Add security headers to all responses"""
        response = await call_next(request)
        
        # FIXED: Updated security headers for better protection
        security_headers = {
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "X-XSS-Protection": "1; mode=block",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Content-Security-Policy": (
                "default-src 'self'; "
                "script-src 'self' 'unsafe-inline' 'unsafe-eval'; "
                "style-src 'self' 'unsafe-inline'; "
                "img-src 'self' data: https:; "
                "font-src 'self' data:; "
                "connect-src 'self'; "
                "media-src 'self'; "
                "object-src 'none'; "
                "child-src 'none'; "
                "frame-ancestors 'none'; "
                "form-action 'self'; "
                "base-uri 'self'"
            ),
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
            "Permissions-Policy": (
                "geolocation=(), "
                "microphone=(), "
                "camera=(), "
                "payment=(), "
                "usb=(), "
                "magnetometer=(), "
                "gyroscope=(), "
                "speaker=()"
            )
        }
        
        # Add headers to response
        for header, value in security_headers.items():
            response.headers[header] = value
        
        # Remove server information
        response.headers.pop("Server", None)
        
        return response


def hash_api_key(api_key: str) -> str:
    """
    Hash API key for secure storage using SHA-256
    
    Args:
        api_key: API key to hash
        
    Returns:
        SHA256 hash of API key
    """
    if not api_key:
        raise ValueError("API key cannot be empty")
    
    return hashlib.sha256(api_key.encode()).hexdigest()


def verify_api_key_format(api_key: str) -> bool:
    """
    Verify API key format with enhanced validation
    
    Args:
        api_key: API key to verify
        
    Returns:
        True if format is valid
    """
    if not api_key or not isinstance(api_key, str):
        return False
    
    if not api_key.startswith(API_KEY_PREFIX):
        return False
    
    # Remove prefix and check remaining length
    token_part = api_key[len(API_KEY_PREFIX):]
    
    # Should be base64-like string with reasonable length
    if len(token_part) < 32:
        return False
    
    # Check if it contains only valid base64 URL-safe characters
    valid_chars = set('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_')
    if not all(c in valid_chars for c in token_part):
        return False
    
    return True


def create_signed_url(
    path: str,
    secret_key: str,
    expiry_minutes: int = 60,
    additional_params: Optional[Dict[str, str]] = None
) -> str:
    """
    Create signed URL with HMAC signature
    
    Args:
        path: URL path
        secret_key: Secret key for signing
        expiry_minutes: URL expiry in minutes
        additional_params: Additional URL parameters
        
    Returns:
        Signed URL
    """
    if not path or not secret_key:
        raise ValueError("Path and secret key are required")
    
    # Calculate expiry timestamp
    expiry_timestamp = int((datetime.now(timezone.utc) + timedelta(minutes=expiry_minutes)).timestamp())
    
    # Build parameters
    params = {
        "expires": str(expiry_timestamp),
        **(additional_params or {})
    }
    
    # Create query string
    query_parts = []
    for key in sorted(params.keys()):
        query_parts.append(f"{key}={urllib.parse.quote(str(params[key]))}")
    query_string = "&".join(query_parts)
    
    # Create signature
    message = f"{path}?{query_string}"
    signature = hmac.new(
        secret_key.encode(),
        message.encode(),
        hashlib.sha256
    ).hexdigest()
    
    # Add signature to URL
    return f"{path}?{query_string}&signature={signature}"


def verify_signed_url(
    url: str,
    secret_key: str
) -> Dict[str, Any]:
    """
    Verify signed URL with enhanced security checks
    
    Args:
        url: Signed URL to verify
        secret_key: Secret key for verification
        
    Returns:
        Verification result
    """
    if not url or not secret_key:
        return {"valid": False, "error": "URL and secret key are required"}
    
    try:
        parsed = urllib.parse.urlparse(url)
        query_params = urllib.parse.parse_qs(parsed.query)
        
        # Check required parameters
        if 'signature' not in query_params or 'expires' not in query_params:
            return {"valid": False, "error": "Missing signature or expiry"}
        
        signature = query_params['signature'][0]
        expires = int(query_params['expires'][0])
        
        # Check expiry
        if datetime.now(timezone.utc).timestamp() > expires:
            return {"valid": False, "error": "URL has expired"}
        
        # Rebuild URL without signature for verification
        verification_params = {k: v[0] for k, v in query_params.items() if k != 'signature'}
        query_parts = []
        for key in sorted(verification_params.keys()):
            query_parts.append(f"{key}={urllib.parse.quote(str(verification_params[key]))}")
        query_string = "&".join(query_parts)
        
        # Calculate expected signature
        message = f"{parsed.path}?{query_string}"
        expected_signature = hmac.new(
            secret_key.encode(),
            message.encode(),
            hashlib.sha256
        ).hexdigest()
        
        # Use constant-time comparison
        if not constant_time_compare(signature, expected_signature):
            return {"valid": False, "error": "Invalid signature"}
        
        return {
            "valid": True,
            "expires_at": datetime.fromtimestamp(expires, tz=timezone.utc),
            "remaining_seconds": expires - datetime.now(timezone.utc).timestamp()
        }
        
    except (ValueError, TypeError, KeyError) as e:
        return {"valid": False, "error": f"Invalid URL format: {e}"}
    except Exception as e:
        logger.error(f"URL verification error: {e}")
        return {"valid": False, "error": "Verification failed"}


def mask_sensitive_data(data: str, mask_char: str = "*", visible_chars: int = 4) -> str:
    """
    Mask sensitive data for logging/display
    
    Args:
        data: Data to mask
        mask_char: Character to use for masking
        visible_chars: Number of characters to leave visible
        
    Returns:
        Masked data
    """
    if not data or len(data) <= visible_chars:
        return mask_char * (len(data) if data else 8)
    
    return data[:visible_chars] + mask_char * (len(data) - visible_chars)


def validate_file_hash(content: bytes, expected_hash: str, algorithm: str = "sha256") -> bool:
    """
    Validate file hash with secure comparison
    
    Args:
        content: File content
        expected_hash: Expected hash value
        algorithm: Hash algorithm
        
    Returns:
        True if hash matches
    """
    try:
        actual_hash = hash_file_content(content, algorithm)
        return constant_time_compare(actual_hash.lower(), expected_hash.lower())
    except Exception as e:
        logger.error(f"File hash validation error: {e}")
        return False


def extract_bearer_token(authorization: str) -> Optional[str]:
    """
    Extract bearer token from authorization header
    
    Args:
        authorization: Authorization header value
        
    Returns:
        Bearer token or None
    """
    if not authorization:
        return None
    
    parts = authorization.split()
    if len(parts) != 2 or parts[0].lower() != 'bearer':
        return None
    
    token = parts[1]
    if not token or len(token) < 10:  # Basic length validation
        return None
    
    return token


def generate_document_reference(prefix: str = "DOC") -> str:
    """
    Generate unique document reference
    
    Args:
        prefix: Reference prefix
        
    Returns:
        Document reference
    """
    timestamp = int(datetime.now(timezone.utc).timestamp())
    random_part = secrets.token_hex(8).upper()
    return f"{prefix}-{timestamp}-{random_part}"


def detect_malicious_input(input_string: str) -> Dict[str, Any]:
    """
    Detect potentially malicious input patterns
    
    Args:
        input_string: Input to analyze
        
    Returns:
        Analysis result
    """
    if not input_string:
        return {"malicious": False, "threats": [], "risk_level": "low"}
    
    threats_detected = []
    
    # Check for XSS patterns
    for pattern in XSS_PATTERNS:
        if re.search(pattern, input_string, re.IGNORECASE):
            threats_detected.append({"type": "xss", "pattern": pattern})
    
    # Check for SQL injection patterns
    for pattern in SQL_INJECTION_PATTERNS:
        if re.search(pattern, input_string, re.IGNORECASE):
            threats_detected.append({"type": "sql_injection", "pattern": pattern})
    
    # Check for path traversal
    if "../" in input_string or "..%2F" in input_string or "..%5C" in input_string:
        threats_detected.append({"type": "path_traversal"})
    
    # Check for null bytes
    if "\x00" in input_string:
        threats_detected.append({"type": "null_byte_injection"})
    
    # Check for command injection patterns
    command_patterns = [r'[;&|`$()]', r'(rm|del|format|sudo|su)', r'(wget|curl|nc|netcat)']
    for pattern in command_patterns:
        if re.search(pattern, input_string, re.IGNORECASE):
            threats_detected.append({"type": "command_injection", "pattern": pattern})
    
    risk_level = "high" if len(threats_detected) > 2 else "medium" if threats_detected else "low"
    
    return {
        "malicious": len(threats_detected) > 0,
        "threats": threats_detected,
        "risk_level": risk_level,
        "threat_count": len(threats_detected)
    }


def create_jwt_token(
    payload: Dict[str, Any],
    secret_key: str,
    algorithm: str = "HS256",
    expiry_minutes: int = 30
) -> str:
    """
    Create JWT token with enhanced security
    
    Args:
        payload: Token payload
        secret_key: Secret key for signing
        algorithm: Signing algorithm
        expiry_minutes: Token expiry in minutes
        
    Returns:
        JWT token
    """
    if not payload or not secret_key:
        raise ValueError("Payload and secret key are required")
    
    if algorithm not in ["HS256", "HS384", "HS512"]:
        raise ValueError(f"Unsupported algorithm: {algorithm}")
    
    now = datetime.now(timezone.utc)
    
    # Add standard claims
    token_payload = {
        **payload,
        "iat": now,
        "exp": now + timedelta(minutes=expiry_minutes),
        "jti": secrets.token_hex(16)  # JWT ID for token tracking
    }
    
    try:
        return jwt.encode(token_payload, secret_key, algorithm=algorithm)
    except Exception as e:
        logger.error(f"JWT token creation failed: {e}")
        raise ValueError("Token creation failed")


def verify_jwt_token(
    token: str,
    secret_key: str,
    algorithm: str = "HS256"
) -> Optional[Dict[str, Any]]:
    """
    Verify JWT token with enhanced error handling
    
    Args:
        token: JWT token to verify
        secret_key: Secret key for verification
        algorithm: Signing algorithm
        
    Returns:
        Decoded payload or None if invalid
    """
    if not token or not secret_key:
        return None
    
    try:
        # FIXED: Updated for PyJWT 2.10.1+ with explicit algorithms
        payload = jwt.decode(
            token, 
            secret_key, 
            algorithms=[algorithm],
            options={
                "require": ["exp", "iat"],  # Require expiration and issued at
                "verify_exp": True,
                "verify_iat": True
            }
        )
        return payload
        
    except ExpiredSignatureError:
        logger.debug("JWT token has expired")
        return None
    except InvalidSignatureError:
        logger.warning("JWT token has invalid signature")
        return None
    except InvalidTokenError as e:
        logger.warning(f"JWT token is invalid: {e}")
        return None
    except PyJWTError as e:
        logger.error(f"JWT token verification error: {e}")
        return None
    except Exception as e:
        logger.error(f"Unexpected JWT error: {e}")
        return None


def constant_time_compare(a: str, b: str) -> bool:
    """
    Constant time string comparison to prevent timing attacks
    
    Args:
        a: First string
        b: Second string
        
    Returns:
        True if strings are equal
    """
    if not isinstance(a, str) or not isinstance(b, str):
        return False
    
    if len(a) != len(b):
        return False
    
    result = 0
    for x, y in zip(a, b):
        result |= ord(x) ^ ord(y)
    
    return result == 0


def generate_csrf_token() -> str:
    """
    Generate CSRF token
    
    Returns:
        CSRF token
    """
    return secrets.token_urlsafe(32)


def hash_file_content(content: bytes, algorithm: str = "sha256") -> str:
    """
    Hash file content with secure algorithms only
    
    Args:
        content: File content as bytes
        algorithm: Hash algorithm (only secure ones allowed)
        
    Returns:
        Hexadecimal hash
    """
    if not isinstance(content, bytes):
        raise ValueError("Content must be bytes")
    
    # FIXED: Only allow secure hash algorithms
    secure_algorithms = {
        "sha256": hashlib.sha256,
        "sha384": hashlib.sha384,
        "sha512": hashlib.sha512,
        "sha3_256": getattr(hashlib, 'sha3_256', None),
        "sha3_384": getattr(hashlib, 'sha3_384', None),
        "sha3_512": getattr(hashlib, 'sha3_512', None),
    }
    
    if algorithm not in secure_algorithms:
        raise ValueError(f"Unsupported or insecure algorithm: {algorithm}. Use one of: {list(secure_algorithms.keys())}")
    
    hasher_func = secure_algorithms[algorithm]
    if hasher_func is None:
        raise ValueError(f"Algorithm {algorithm} not available in this Python version")
    
    hasher = hasher_func()
    hasher.update(content)
    return hasher.hexdigest()


def secure_filename(filename: str) -> str:
    """
    Secure filename by removing potentially dangerous characters
    
    Args:
        filename: Original filename
        
    Returns:
        Secured filename
    """
    if not filename:
        return f"file_{secrets.token_hex(8)}"
    
    # Remove directory traversal patterns
    filename = filename.replace('..', '').replace('/', '').replace('\\', '')
    
    # Remove dangerous characters and normalize
    filename = re.sub(r'[^\w\s\-_\.]', '', filename)
    filename = re.sub(r'\s+', '_', filename)  # Replace spaces with underscores
    
    # Limit length and handle extension
    name_parts = filename.rsplit('.', 1)
    if len(name_parts) == 2:
        name, ext = name_parts
        name = name[:200]  # Limit name part
        ext = ext[:10]     # Limit extension part
        filename = f"{name}.{ext}" if name else f"file_{secrets.token_hex(4)}.{ext}"
    else:
        filename = filename[:255]
    
    # Ensure it's not empty or hidden file without name
    if not filename or filename.startswith('.'):
        filename = f"file_{secrets.token_hex(8)}" + (f".{name_parts[-1]}" if '.' in filename else '')
    
    return filename.strip()


def check_rate_limit(
    identifier: str,
    limit: int,
    window_seconds: int,
    storage: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Enhanced in-memory rate limiting check with cleanup
    
    Args:
        identifier: Unique identifier (IP, user ID, etc.)
        limit: Maximum requests per window
        window_seconds: Time window in seconds
        storage: In-memory storage dict
        
    Returns:
        Rate limit check result
    """
    now = time.time()
    
    # Clean old entries periodically
    if len(storage) > 10000:  # Prevent memory bloat
        cutoff = now - (window_seconds * 2)
        expired_keys = [k for k, v in storage.items() if v.get('window_start', 0) < cutoff]
        for key in expired_keys[:1000]:  # Clean max 1000 at a time
            storage.pop(key, None)
    
    if identifier not in storage:
        storage[identifier] = {
            'count': 1,
            'window_start': now,
            'first_request': now
        }
        return {
            "allowed": True,
            "requests_made": 1,
            "requests_remaining": limit - 1,
            "reset_time": now + window_seconds
        }
    
    entry = storage[identifier]
    
    # Check if we're in a new window
    if now - entry['window_start'] >= window_seconds:
        entry['count'] = 1
        entry['window_start'] = now
        return {
            "allowed": True,
            "requests_made": 1,
            "requests_remaining": limit - 1,
            "reset_time": now + window_seconds
        }
    
    # Increment count
    entry['count'] += 1
    
    if entry['count'] <= limit:
        return {
            "allowed": True,
            "requests_made": entry['count'],
            "requests_remaining": max(0, limit - entry['count']),
            "reset_time": entry['window_start'] + window_seconds
        }
    else:
        return {
            "allowed": False,
            "requests_made": entry['count'],
            "requests_remaining": 0,
            "reset_time": entry['window_start'] + window_seconds,
            "retry_after": entry['window_start'] + window_seconds - now
        }


def generate_secure_filename_with_hash(original_filename: str, content_hash: str) -> str:
    """
    Generate secure filename incorporating content hash
    
    Args:
        original_filename: Original filename
        content_hash: Content hash (first 16 chars will be used)
        
    Returns:
        Secure filename with hash prefix
    """
    secure_name = secure_filename(original_filename)
    hash_prefix = content_hash[:16] if content_hash else secrets.token_hex(8)
    
    name_parts = secure_name.rsplit('.', 1)
    if len(name_parts) == 2:
        return f"{hash_prefix}_{name_parts[0]}.{name_parts[1]}"
    else:
        return f"{hash_prefix}_{secure_name}"


# Password strength validation with zxcvbn-style feedback
def get_password_feedback(password: str) -> Dict[str, Any]:
    """
    Get detailed password feedback similar to zxcvbn
    
    Args:
        password: Password to analyze
        
    Returns:
        Detailed feedback dictionary
    """
    if not password:
        return {
            "score": 0,
            "feedback": "Password is required",
            "suggestions": ["Choose a password with at least 8 characters"]
        }
    
    score = 0
    suggestions = []
    warning = None
    
    # Length scoring
    if len(password) < 8:
        warning = "Password is too short"
        suggestions.append("Use at least 8 characters")
    elif len(password) < 10:
        score += 1
        suggestions.append("Consider using 12+ characters for better security")
    elif len(password) < 12:
        score += 2
    else:
        score += 3
    
    # Character variety
    char_types = 0
    if re.search(r'[a-z]', password):
        char_types += 1
    else:
        suggestions.append("Add lowercase letters")
    
    if re.search(r'[A-Z]', password):
        char_types += 1
    else:
        suggestions.append("Add uppercase letters")
    
    if re.search(r'\d', password):
        char_types += 1
    else:
        suggestions.append("Add numbers")
    
    if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        char_types += 1
    else:
        suggestions.append("Add special characters")
    
    score += char_types
    
    # Common patterns penalty
    if password.lower() in COMMON_PASSWORDS:
        score = max(0, score - 3)
        warning = "This is a commonly used password"
        suggestions.append("Choose a less common password")
    
    # Repetition penalty
    if len(set(password)) < len(password) * 0.6:
        score = max(0, score - 2)
        if not warning:
            warning = "Password has too many repeated characters"
        suggestions.append("Avoid repeated characters and patterns")
    
    # Simple sequence detection
    sequences = ['123', 'abc', 'qwe', 'asd', 'zxc']
    for seq in sequences:
        if seq in password.lower():
            score = max(0, score - 1)
            if not warning:
                warning = "Avoid common sequences"
            break
    
    # Final score adjustment
    score = min(4, max(0, score))
    
    strength_levels = {
        0: "Very Weak",
        1: "Weak", 
        2: "Fair",
        3: "Good",
        4: "Strong"
    }
    
    return {
        "score": score,
        "strength": strength_levels[score],
        "warning": warning,
        "suggestions": suggestions[:3],  # Limit suggestions
        "character_types": char_types,
        "length": len(password)
    }
