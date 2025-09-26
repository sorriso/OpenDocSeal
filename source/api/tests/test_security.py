"""
Path: infrastructure/source/api/tests/test_security.py
Version: 2
"""

import pytest
import jwt
import time
from datetime import datetime, timezone, timedelta
from unittest.mock import patch, MagicMock

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.security import (
    generate_secure_token, generate_api_key, hash_password, verify_password,
    validate_password_strength, sanitize_input, validate_email, validate_url,
    hash_api_key, verify_api_key_format, create_signed_url, verify_signed_url,
    mask_sensitive_data, validate_file_hash, extract_bearer_token,
    generate_document_reference, detect_malicious_input, create_jwt_token,
    verify_jwt_token, constant_time_compare, generate_csrf_token,
    hash_file_content, secure_filename, get_password_feedback
)


class TestPasswordSecurity:
    """Test password security functions"""
    
    def test_hash_password_valid(self):
        """Test password hashing with valid input"""
        password = "SecurePass123!"
        hashed = hash_password(password)
        
        assert hashed is not None
        assert isinstance(hashed, str)
        assert len(hashed) > 50  # Bcrypt hash should be long
        assert hashed != password  # Should not be plaintext
        assert hashed.startswith('$2b$')  # Should use bcrypt 2b prefix
        
    def test_hash_password_empty(self):
        """Test password hashing with empty input"""
        with pytest.raises(ValueError, match="Password cannot be empty"):
            hash_password("")
            
    def test_hash_password_none(self):
        """Test password hashing with None input"""
        with pytest.raises(ValueError, match="Password cannot be empty"):
            hash_password(None)
    
    def test_hash_password_too_long(self):
        """Test password hashing with overly long input"""
        long_password = "a" * 200
        with pytest.raises(ValueError, match="Password cannot exceed"):
            hash_password(long_password)
    
    def test_verify_password_valid(self):
        """Test password verification with valid credentials"""
        password = "SecurePass123!"
        hashed = hash_password(password)
        
        assert verify_password(password, hashed) == True
        assert verify_password("WrongPassword", hashed) == False
        
    def test_verify_password_invalid_hash(self):
        """Test password verification with invalid hash"""
        password = "SecurePass123!"
        invalid_hash = "not_a_valid_hash"
        
        assert verify_password(password, invalid_hash) == False
        
    def test_verify_password_empty_inputs(self):
        """Test password verification with empty inputs"""
        assert verify_password("", "hash") == False
        assert verify_password("password", "") == False
        assert verify_password("", "") == False
        
    def test_validate_password_strength_valid(self):
        """Test password strength validation with valid passwords"""
        valid_passwords = [
            "SecurePass123!",
            "MyStr0ng@Password",
            "C0mpl3x!P@ssw0rd",
        ]
        
        for password in valid_passwords:
            result = validate_password_strength(password)
            assert result["valid"] == True, f"Password should be valid: {password}"
            assert result["score"] > 0
            assert result["strength"] in ["medium", "strong"]
            
    def test_validate_password_strength_invalid(self):
        """Test password strength validation with invalid passwords"""
        invalid_cases = [
            ("short", "too short"),
            ("nouppercase123!", "no uppercase"),
            ("NOLOWERCASE123!", "no lowercase"),
            ("NoNumbers!", "no numbers"),
            ("NoSpecial123", "no special characters"),
            ("password", "common password"),
        ]
        
        for password, reason in invalid_cases:
            result = validate_password_strength(password)
            assert result["valid"] == False, f"Password should be invalid ({reason}): {password}"
            assert len(result["issues"]) > 0
    
    def test_validate_password_strength_empty(self):
        """Test password strength validation with empty password"""
        result = validate_password_strength("")
        assert result["valid"] == False
        assert result["score"] == 0
        assert "empty" in result["issues"][0].lower()
    
    def test_get_password_feedback(self):
        """Test detailed password feedback function"""
        test_cases = [
            ("", 0, "required"),
            ("short", 0, "too short"),
            ("verylongpasswordwithgoodlength", 1, None),
            ("VeryLongPassword123!", 4, None),
        ]
        
        for password, expected_min_score, expected_warning in test_cases:
            result = get_password_feedback(password)
            assert "score" in result
            assert "strength" in result
            assert "suggestions" in result
            
            if expected_min_score > 0:
                assert result["score"] >= expected_min_score
            
            if expected_warning:
                assert result.get("warning") and expected_warning in result["warning"].lower()


class TestTokenSecurity:
    """Test token generation and validation"""
    
    @pytest.fixture
    def test_secret(self):
        """Test secret key"""
        return "test_secret_key_that_is_long_enough_for_security"
    
    def test_generate_secure_token(self):
        """Test secure token generation"""
        token = generate_secure_token()
        assert token is not None
        assert isinstance(token, str)
        assert len(token) > 20  # URL-safe base64 should be reasonably long
        
        # Test different lengths
        short_token = generate_secure_token(16)
        long_token = generate_secure_token(64)
        assert len(short_token) < len(long_token)
    
    def test_generate_api_key(self):
        """Test API key generation"""
        api_key = generate_api_key()
        assert api_key.startswith("odseal_")
        assert len(api_key) > 40
        assert verify_api_key_format(api_key) == True
    
    def test_verify_api_key_format_valid(self):
        """Test API key format validation with valid keys"""
        valid_api_key = generate_api_key()
        assert verify_api_key_format(valid_api_key) == True
    
    def test_verify_api_key_format_invalid(self):
        """Test API key format validation with invalid keys"""
        invalid_keys = [
            "",
            "invalid_key",
            "odseal_",
            "odseal_short",
            "wrong_prefix_long_token_here",
            None
        ]
        
        for key in invalid_keys:
            assert verify_api_key_format(key) == False
    
    def test_hash_api_key(self):
        """Test API key hashing"""
        api_key = generate_api_key()
        hashed = hash_api_key(api_key)
        
        assert hashed is not None
        assert isinstance(hashed, str)
        assert len(hashed) == 64  # SHA256 hex length
        assert hashed != api_key
        
    def test_hash_api_key_empty(self):
        """Test API key hashing with empty input"""
        with pytest.raises(ValueError, match="API key cannot be empty"):
            hash_api_key("")


class TestJWTSecurity:
    """Test JWT token functions with updated PyJWT"""
    
    @pytest.fixture
    def test_secret(self):
        """Test secret key"""
        return "test_secret_key_that_is_long_enough_for_jwt_security"
    
    def test_create_jwt_token_valid(self, test_secret):
        """Test JWT token creation with valid input"""
        payload = {"user_id": "123", "email": "test@example.com"}
        token = create_jwt_token(payload, test_secret, expiry_minutes=60)
        
        assert token is not None
        assert isinstance(token, str)
        assert len(token.split('.')) == 3  # Header.Payload.Signature
        
    def test_create_jwt_token_invalid_algorithm(self, test_secret):
        """Test JWT token creation with invalid algorithm"""
        payload = {"user_id": "123"}
        
        with pytest.raises(ValueError, match="Unsupported algorithm"):
            create_jwt_token(payload, test_secret, algorithm="INVALID")
    
    def test_create_jwt_token_empty_inputs(self, test_secret):
        """Test JWT token creation with empty inputs"""
        with pytest.raises(ValueError, match="Payload and secret key are required"):
            create_jwt_token({}, test_secret)
        
        with pytest.raises(ValueError, match="Payload and secret key are required"):
            create_jwt_token({"user": "123"}, "")
        
    def test_verify_jwt_token_valid(self, test_secret):
        """Test JWT token verification with valid token"""
        payload = {"user_id": "123", "email": "test@example.com"}
        token = create_jwt_token(payload, test_secret, expiry_minutes=60)
        
        decoded = verify_jwt_token(token, test_secret)
        
        assert decoded is not None
        assert decoded["user_id"] == "123"
        assert decoded["email"] == "test@example.com"
        assert "exp" in decoded
        assert "iat" in decoded
        assert "jti" in decoded  # JWT ID should be added
        
    def test_verify_jwt_token_expired(self, test_secret):
        """Test JWT token verification with expired token"""
        payload = {"user_id": "123", "email": "test@example.com"}
        token = create_jwt_token(payload, test_secret, expiry_minutes=-1)  # Already expired
        
        # Wait a moment to ensure expiration
        time.sleep(0.1)
        
        decoded = verify_jwt_token(token, test_secret)
        assert decoded is None
        
    def test_verify_jwt_token_invalid_signature(self, test_secret):
        """Test JWT token verification with invalid signature"""
        payload = {"user_id": "123", "email": "test@example.com"}
        token = create_jwt_token(payload, test_secret, expiry_minutes=60)
        
        # Try to verify with different secret
        decoded = verify_jwt_token(token, "wrong_secret_key_for_testing")
        assert decoded is None
    
    def test_verify_jwt_token_malformed(self, test_secret):
        """Test JWT token verification with malformed token"""
        malformed_tokens = [
            "",
            "invalid.token",
            "invalid",
            "a.b",  # Missing signature
            None
        ]
        
        for token in malformed_tokens:
            decoded = verify_jwt_token(token, test_secret)
            assert decoded is None


class TestInputSecurity:
    """Test input validation and sanitization"""
    
    def test_sanitize_input_normal(self):
        """Test input sanitization with normal text"""
        clean_input = "This is normal text"
        result = sanitize_input(clean_input)
        assert result == clean_input
    
    def test_sanitize_input_xss(self):
        """Test input sanitization with XSS attempts"""
        malicious_inputs = [
            "<script>alert('xss')</script>",
            "javascript:alert('xss')",
            "<img src='x' onerror='alert(1)'>",
            "Text with <script> tags",
        ]
        
        for malicious_input in malicious_inputs:
            result = sanitize_input(malicious_input)
            assert "<script>" not in result
            assert "javascript:" not in result
            assert "onerror" not in result or "&" in result  # Should be encoded
    
    def test_sanitize_input_length_limit(self):
        """Test input sanitization with length limit"""
        long_input = "a" * 2000
        result = sanitize_input(long_input, max_length=100)
        assert len(result) <= 100
    
    def test_sanitize_input_null_bytes(self):
        """Test input sanitization removes null bytes"""
        input_with_nulls = "text\x00with\x00nulls"
        result = sanitize_input(input_with_nulls)
        assert "\x00" not in result
    
    def test_detect_malicious_input(self):
        """Test malicious input detection"""
        test_cases = [
            ("normal text", False, "low"),
            ("<script>alert('xss')</script>", True, "medium"),
            ("' OR 1=1 --", True, "medium"),
            ("../../../etc/passwd", True, "medium"),
            ("<script>alert('xss')</script>' OR 1=1 --", True, "high"),
        ]
        
        for input_text, should_be_malicious, expected_risk in test_cases:
            result = detect_malicious_input(input_text)
            assert result["malicious"] == should_be_malicious
            assert result["risk_level"] == expected_risk
            
            if should_be_malicious:
                assert len(result["threats"]) > 0
    
    def test_validate_email_valid(self):
        """Test email validation with valid emails"""
        valid_emails = [
            "user@example.com",
            "test.email@domain.co.uk", 
            "user+tag@example.org",
        ]
        
        for email in valid_emails:
            result = validate_email(email)
            assert result["valid"] == True
            assert "email" in result
            assert result["email"] == email.lower()
    
    def test_validate_email_invalid(self):
        """Test email validation with invalid emails"""
        invalid_emails = [
            "",
            "not-an-email",
            "@example.com",
            "user@",
            "user name@example.com",
            "user@example..com",  # Double dot
        ]
        
        for email in invalid_emails:
            result = validate_email(email)
            assert result["valid"] == False
            assert "error" in result
    
    def test_validate_url_valid(self):
        """Test URL validation with valid URLs"""
        valid_urls = [
            "https://example.com",
            "http://test.domain.org/path",
            "https://sub.domain.com:8080/path?query=value",
        ]
        
        for url in valid_urls:
            result = validate_url(url)
            assert result["valid"] == True
            assert "domain" in result
    
    def test_validate_url_invalid(self):
        """Test URL validation with invalid URLs"""
        invalid_urls = [
            "",
            "not-a-url",
            "ftp://example.com",  # Not in allowed schemes
            "https://",
            "https://localhost",  # Localhost not allowed
        ]
        
        for url in invalid_urls:
            result = validate_url(url)
            assert result["valid"] == False
            assert "error" in result


class TestFileOperations:
    """Test file-related security functions"""
    
    def test_hash_file_content_sha256(self):
        """Test file content hashing with SHA256"""
        test_content = b"This is test file content"
        hash_result = hash_file_content(test_content, "sha256")
        
        assert hash_result is not None
        assert isinstance(hash_result, str)
        assert len(hash_result) == 64  # SHA256 hex length
        
        # Test consistency
        hash_result2 = hash_file_content(test_content, "sha256")
        assert hash_result == hash_result2
    
    def test_hash_file_content_different_algorithms(self):
        """Test file content hashing with different algorithms"""
        test_content = b"Test content"
        
        sha256_hash = hash_file_content(test_content, "sha256")
        sha384_hash = hash_file_content(test_content, "sha384")
        sha512_hash = hash_file_content(test_content, "sha512")
        
        assert len(sha256_hash) == 64
        assert len(sha384_hash) == 96
        assert len(sha512_hash) == 128
        assert sha256_hash != sha384_hash != sha512_hash
    
    def test_hash_file_content_insecure_algorithm(self):
        """Test file content hashing rejects insecure algorithms"""
        test_content = b"Test content"
        
        with pytest.raises(ValueError, match="Unsupported or insecure algorithm"):
            hash_file_content(test_content, "md5")
        
        with pytest.raises(ValueError, match="Unsupported or insecure algorithm"):
            hash_file_content(test_content, "sha1")
    
    def test_validate_file_hash(self):
        """Test file hash validation"""
        test_content = b"Test file content"
        correct_hash = hash_file_content(test_content)
        wrong_hash = "0" * 64
        
        assert validate_file_hash(test_content, correct_hash) == True
        assert validate_file_hash(test_content, wrong_hash) == False
        
    def test_secure_filename(self):
        """Test secure filename generation"""
        test_cases = [
            ("normal_file.txt", "normal_file.txt"),
            ("file with spaces.pdf", "file_with_spaces.pdf"),
            ("../../../etc/passwd", "etc_passwd"),
            ("file<>:\"/\\|?*.txt", "file_.txt"),
            ("", None),  # Should generate a random name
            ("...hidden", None),  # Should generate a random name
        ]
        
        for input_filename, expected_pattern in test_cases:
            result = secure_filename(input_filename)
            assert result is not None
            assert isinstance(result, str)
            assert len(result) > 0
            
            if expected_pattern:
                if expected_pattern.endswith(".txt"):
                    assert result.endswith(".txt")
                else:
                    assert expected_pattern in result
            else:
                # Should have generated a random name
                assert "file_" in result
            
            # Should not contain dangerous characters
            dangerous_chars = ['<', '>', ':', '"', '/', '\\', '|', '?', '*']
            assert not any(char in result for char in dangerous_chars)


class TestUtilityFunctions:
    """Test utility security functions"""
    
    def test_constant_time_compare(self):
        """Test constant time string comparison"""
        assert constant_time_compare("hello", "hello") == True
        assert constant_time_compare("hello", "world") == False
        assert constant_time_compare("", "") == True
        assert constant_time_compare("hello", "hello123") == False
        assert constant_time_compare("", "hello") == False
    
    def test_mask_sensitive_data(self):
        """Test sensitive data masking"""
        test_cases = [
            ("user@example.com", "user*************"),
            ("short", "****"),
            ("", "********"),
            ("1234567890", "1234******"),
        ]
        
        for input_data, expected_pattern in test_cases:
            result = mask_sensitive_data(input_data)
            assert len(result) >= len(expected_pattern.replace('*', ''))
            if input_data:
                assert result.startswith(input_data[:4] if len(input_data) > 4 else "")
    
    def test_extract_bearer_token(self):
        """Test bearer token extraction"""
        valid_header = "Bearer abc123xyz789"
        assert extract_bearer_token(valid_header) == "abc123xyz789"
        
        invalid_headers = [
            "",
            "Basic abc123",
            "Bearer",
            "Bearer ",
            "Bearer short",
            None
        ]
        
        for header in invalid_headers:
            assert extract_bearer_token(header) is None
    
    def test_generate_document_reference(self):
        """Test document reference generation"""
        ref1 = generate_document_reference()
        ref2 = generate_document_reference("TEST")
        
        assert ref1.startswith("DOC-")
        assert ref2.startswith("TEST-")
        assert ref1 != ref2
        assert len(ref1.split('-')) == 3
        assert len(ref2.split('-')) == 3
    
    def test_generate_csrf_token(self):
        """Test CSRF token generation"""
        token1 = generate_csrf_token()
        token2 = generate_csrf_token()
        
        assert token1 != token2
        assert len(token1) > 20
        assert len(token2) > 20


class TestSignedURLs:
    """Test signed URL functionality"""
    
    @pytest.fixture
    def test_secret(self):
        return "test_secret_for_url_signing"
    
    def test_create_signed_url(self, test_secret):
        """Test signed URL creation"""
        path = "/api/documents/download"
        signed_url = create_signed_url(path, test_secret, expiry_minutes=60)
        
        assert signed_url.startswith(path)
        assert "expires=" in signed_url
        assert "signature=" in signed_url
    
    def test_verify_signed_url_valid(self, test_secret):
        """Test signed URL verification with valid URL"""
        path = "/api/documents/download"
        signed_url = create_signed_url(path, test_secret, expiry_minutes=60)
        
        result = verify_signed_url(signed_url, test_secret)
        assert result["valid"] == True
        assert result["remaining_seconds"] > 0
    
    def test_verify_signed_url_expired(self, test_secret):
        """Test signed URL verification with expired URL"""
        path = "/api/documents/download"
        signed_url = create_signed_url(path, test_secret, expiry_minutes=-1)  # Already expired
        
        result = verify_signed_url(signed_url, test_secret)
        assert result["valid"] == False
        assert "expired" in result["error"].lower()
    
    def test_verify_signed_url_tampered(self, test_secret):
        """Test signed URL verification with tampered URL"""
        path = "/api/documents/download"
        signed_url = create_signed_url(path, test_secret, expiry_minutes=60)
        
        # Tamper with the URL
        tampered_url = signed_url.replace("download", "upload")
        
        result = verify_signed_url(tampered_url, test_secret)
        assert result["valid"] == False
        assert "signature" in result["error"].lower()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])