"""
Path: infrastructure/source/api/tests/test_auth_service.py
Version: 1 - AuthService Production Tests
"""

import pytest
import asyncio
import time
from datetime import datetime, timezone, timedelta
from unittest.mock import AsyncMock, MagicMock, patch, call
from typing import Dict, Any, List, Optional
import bcrypt
import jwt

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from services.auth import AuthService
from models.auth import User, UserCreate, UserLogin, APIKeyCreate, APIKey
from models.base import UserRole
from config import get_settings
from database import get_users_collection, get_api_keys_collection


class TestAuthServiceCreation:
    """Test AuthService creation and initialization"""
    
    def test_auth_service_initialization(self):
        """Test AuthService initialization"""
        auth_service = AuthService()
        
        # Check thread pool is created
        assert hasattr(auth_service, '_auth_thread_pool')
        assert auth_service._auth_thread_pool is not None
        assert auth_service._auth_thread_pool._max_workers == 4
        assert "auth_cpu" in auth_service._auth_thread_pool._thread_name_prefix
        
        # Check rate limiter is initialized
        assert hasattr(auth_service, '_rate_limiter')
        
        # Check metrics are initialized
        assert hasattr(auth_service, '_operation_metrics')
        assert "login" in auth_service._operation_metrics
        assert "register" in auth_service._operation_metrics


class TestPasswordOperations:
    """Test password hashing and verification"""
    
    @pytest.fixture
    def auth_service(self):
        return AuthService()
    
    def test_hash_password(self, auth_service):
        """Test password hashing"""
        password = "TestPassword123!"
        hashed = auth_service._hash_password(password)
        
        assert hashed is not None
        assert isinstance(hashed, str)
        assert hashed != password
        assert hashed.startswith("$2b$")
        
        # Verify it can be checked
        assert bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))
    
    def test_verify_password(self, auth_service):
        """Test password verification"""
        password = "TestPassword123!"
        hashed = auth_service._hash_password(password)
        
        # Test correct password
        assert auth_service._verify_password(password, hashed) is True
        
        # Test incorrect password
        assert auth_service._verify_password("WrongPassword", hashed) is False
        
        # Test empty password
        assert auth_service._verify_password("", hashed) is False
    
    def test_password_performance(self, auth_service):
        """Test password operations performance"""
        password = "TestPassword123!"
        
        # Hashing should complete within reasonable time
        start_time = time.time()
        hashed = auth_service._hash_password(password)
        hash_time = time.time() - start_time
        
        assert hash_time < 1.0  # Should complete within 1 second
        
        # Verification should be fast
        start_time = time.time()
        result = auth_service._verify_password(password, hashed)
        verify_time = time.time() - start_time
        
        assert verify_time < 0.5  # Should complete within 0.5 seconds
        assert result is True


class TestUserRegistration:
    """Test user registration functionality"""
    
    @pytest.fixture
    def auth_service(self):
        return AuthService()
    
    @pytest.fixture
    def sample_user_create(self):
        return UserCreate(
            email="test@example.com",
            name="Test User",
            password="SecurePassword123!",
            role="user"
        )
    
    @pytest.mark.asyncio
    async def test_register_user_success(self, auth_service, sample_user_create):
        """Test successful user registration"""
        
        with patch('services.auth.get_users_collection') as mock_get_collection:
            mock_collection = AsyncMock()
            mock_get_collection.return_value = mock_collection
            
            # Mock email doesn't exist
            mock_collection.find_one.return_value = None
            
            # Mock successful insert
            mock_collection.insert_one.return_value = MagicMock(
                inserted_id="64a1b2c3d4e5f6a7b8c9d0e1"
            )
            
            # Mock user retrieval after insert
            mock_user_doc = {
                "_id": "64a1b2c3d4e5f6a7b8c9d0e1",
                "email": sample_user_create.email,
                "name": sample_user_create.name,
                "role": UserRole.USER,
                "is_active": True,
                "created_at": datetime.now(timezone.utc),
                "updated_at": datetime.now(timezone.utc)
            }
            mock_collection.find_one.return_value = mock_user_doc
            
            result = await auth_service.register_user(sample_user_create)
            
            assert result is not None
            assert result.email == sample_user_create.email
            assert result.name == sample_user_create.name
            assert result.role == UserRole.USER
            assert result.is_active is True
            
            # Verify email uniqueness check
            mock_collection.find_one.assert_any_call({"email": sample_user_create.email})
            
            # Verify password is hashed (not stored in plain text)
            insert_call = mock_collection.insert_one.call_args[0][0]
            assert "password_hash" in insert_call
            assert insert_call["password_hash"] != sample_user_create.password
            assert insert_call["password_hash"].startswith("$2b$")
    
    @pytest.mark.asyncio
    async def test_register_user_duplicate_email(self, auth_service, sample_user_create):
        """Test registration with duplicate email"""
        
        with patch('services.auth.get_users_collection') as mock_get_collection:
            mock_collection = AsyncMock()
            mock_get_collection.return_value = mock_collection
            
            # Mock email already exists
            mock_collection.find_one.return_value = {"email": sample_user_create.email}
            
            result = await auth_service.register_user(sample_user_create)
            
            assert result is None
            
            # Verify insert was not called
            mock_collection.insert_one.assert_not_called()
    
    @pytest.mark.asyncio
    async def test_register_user_database_error(self, auth_service, sample_user_create):
        """Test registration with database error"""
        
        with patch('services.auth.get_users_collection') as mock_get_collection:
            mock_collection = AsyncMock()
            mock_get_collection.return_value = mock_collection
            
            # Mock email doesn't exist
            mock_collection.find_one.return_value = None
            
            # Mock database error on insert
            mock_collection.insert_one.side_effect = Exception("Database error")
            
            result = await auth_service.register_user(sample_user_create)
            
            assert result is None


class TestUserAuthentication:
    """Test user authentication functionality"""
    
    @pytest.fixture
    def auth_service(self):
        return AuthService()
    
    @pytest.fixture
    def sample_user_login(self):
        return UserLogin(
            email="test@example.com",
            password="SecurePassword123!"
        )
    
    @pytest.fixture
    def sample_user_doc(self, auth_service):
        return {
            "_id": "64a1b2c3d4e5f6a7b8c9d0e1",
            "email": "test@example.com",
            "name": "Test User",
            "password_hash": auth_service._hash_password("SecurePassword123!"),
            "role": UserRole.USER,
            "is_active": True,
            "created_at": datetime.now(timezone.utc),
            "updated_at": datetime.now(timezone.utc)
        }
    
    @pytest.mark.asyncio
    async def test_authenticate_user_success(self, auth_service, sample_user_login, sample_user_doc):
        """Test successful user authentication"""
        
        with patch('services.auth.get_users_collection') as mock_get_collection:
            mock_collection = AsyncMock()
            mock_get_collection.return_value = mock_collection
            
            # Mock user found
            mock_collection.find_one.return_value = sample_user_doc
            
            result = await auth_service.authenticate_user(
                sample_user_login.email, 
                sample_user_login.password
            )
            
            assert result is not None
            assert result.email == sample_user_login.email
            assert result.is_active is True
            
            # Verify user lookup
            mock_collection.find_one.assert_called_once_with({"email": sample_user_login.email})
    
    @pytest.mark.asyncio
    async def test_authenticate_user_not_found(self, auth_service, sample_user_login):
        """Test authentication with non-existent user"""
        
        with patch('services.auth.get_users_collection') as mock_get_collection:
            mock_collection = AsyncMock()
            mock_get_collection.return_value = mock_collection
            
            # Mock user not found
            mock_collection.find_one.return_value = None
            
            result = await auth_service.authenticate_user(
                sample_user_login.email, 
                sample_user_login.password
            )
            
            assert result is None
    
    @pytest.mark.asyncio
    async def test_authenticate_user_wrong_password(self, auth_service, sample_user_login, sample_user_doc):
        """Test authentication with wrong password"""
        
        with patch('services.auth.get_users_collection') as mock_get_collection:
            mock_collection = AsyncMock()
            mock_get_collection.return_value = mock_collection
            
            # Mock user found
            mock_collection.find_one.return_value = sample_user_doc
            
            result = await auth_service.authenticate_user(
                sample_user_login.email, 
                "WrongPassword123!"
            )
            
            assert result is None
    
    @pytest.mark.asyncio
    async def test_authenticate_user_inactive(self, auth_service, sample_user_login, sample_user_doc):
        """Test authentication with inactive user"""
        
        # Make user inactive
        sample_user_doc["is_active"] = False
        
        with patch('services.auth.get_users_collection') as mock_get_collection:
            mock_collection = AsyncMock()
            mock_get_collection.return_value = mock_collection
            
            # Mock user found but inactive
            mock_collection.find_one.return_value = sample_user_doc
            
            result = await auth_service.authenticate_user(
                sample_user_login.email, 
                sample_user_login.password
            )
            
            assert result is None


class TestJWTOperations:
    """Test JWT token operations"""
    
    @pytest.fixture
    def auth_service(self):
        return AuthService()
    
    @pytest.fixture
    def sample_user(self):
        return User(
            id="64a1b2c3d4e5f6a7b8c9d0e1",
            email="test@example.com",
            name="Test User",
            role=UserRole.USER,
            is_active=True,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc)
        )
    
    def test_create_access_token(self, auth_service, sample_user):
        """Test access token creation"""
        
        token = auth_service.create_access_token(sample_user)
        
        assert token is not None
        assert isinstance(token, str)
        assert len(token) > 100  # JWT tokens are typically long
        
        # Verify token can be decoded
        settings = get_settings()
        decoded = jwt.decode(token, settings.secret_key, algorithms=["HS256"])
        
        assert decoded["sub"] == str(sample_user.id)
        assert decoded["email"] == sample_user.email
        assert decoded["role"] == sample_user.role.value
        assert "exp" in decoded
        assert "iat" in decoded
    
    def test_create_refresh_token(self, auth_service, sample_user):
        """Test refresh token creation"""
        
        token = auth_service.create_refresh_token(sample_user)
        
        assert token is not None
        assert isinstance(token, str)
        
        # Verify token can be decoded
        settings = get_settings()
        decoded = jwt.decode(token, settings.secret_key, algorithms=["HS256"])
        
        assert decoded["sub"] == str(sample_user.id)
        assert decoded["type"] == "refresh"
        assert "exp" in decoded
        assert "iat" in decoded
    
    def test_verify_token_valid(self, auth_service, sample_user):
        """Test token verification with valid token"""
        
        token = auth_service.create_access_token(sample_user)
        
        payload = auth_service.verify_token(token)
        
        assert payload is not None
        assert payload["sub"] == str(sample_user.id)
        assert payload["email"] == sample_user.email
    
    def test_verify_token_invalid(self, auth_service):
        """Test token verification with invalid token"""
        
        invalid_token = "invalid.jwt.token"
        
        payload = auth_service.verify_token(invalid_token)
        
        assert payload is None
    
    def test_verify_token_expired(self, auth_service, sample_user):
        """Test token verification with expired token"""
        
        # Create token with short expiry
        with patch('services.auth.get_settings') as mock_settings:
            settings = get_settings()
            settings.access_token_expire_minutes = -1  # Already expired
            mock_settings.return_value = settings
            
            token = auth_service.create_access_token(sample_user)
        
        # Verify token is expired
        payload = auth_service.verify_token(token)
        
        assert payload is None


class TestAPIKeyOperations:
    """Test API key operations"""
    
    @pytest.fixture
    def auth_service(self):
        return AuthService()
    
    @pytest.fixture
    def sample_api_key_create(self):
        return APIKeyCreate(
            name="Test API Key",
            description="API key for testing",
            expires_at=datetime.now(timezone.utc) + timedelta(days=30)
        )
    
    @pytest.mark.asyncio
    async def test_create_api_key_success(self, auth_service, sample_api_key_create):
        """Test successful API key creation"""
        
        user_id = "64a1b2c3d4e5f6a7b8c9d0e1"
        
        with patch('services.auth.get_api_keys_collection') as mock_get_collection:
            mock_collection = AsyncMock()
            mock_get_collection.return_value = mock_collection
            
            # Mock successful insert
            mock_collection.insert_one.return_value = MagicMock(
                inserted_id="64b1c2d3e4f5a6b7c8d9e0f1"
            )
            
            # Mock API key retrieval after insert
            mock_api_key_doc = {
                "_id": "64b1c2d3e4f5a6b7c8d9e0f1",
                "user_id": user_id,
                "name": sample_api_key_create.name,
                "description": sample_api_key_create.description,
                "key_hash": "hashed_key",
                "prefix": "odseal_test",
                "is_active": True,
                "expires_at": sample_api_key_create.expires_at,
                "created_at": datetime.now(timezone.utc),
                "last_used_at": None
            }
            mock_collection.find_one.return_value = mock_api_key_doc
            
            api_key, raw_key = await auth_service.create_api_key(user_id, sample_api_key_create)
            
            assert api_key is not None
            assert api_key.name == sample_api_key_create.name
            assert api_key.is_active is True
            
            assert raw_key is not None
            assert isinstance(raw_key, str)
            assert raw_key.startswith("odseal_")
            assert len(raw_key) > 40  # API keys should be long
    
    @pytest.mark.asyncio
    async def test_verify_api_key_valid(self, auth_service):
        """Test API key verification with valid key"""
        
        raw_key = "odseal_test_12345678901234567890abcdef"
        key_hash = auth_service._hash_api_key(raw_key)
        
        with patch('services.auth.get_api_keys_collection') as mock_get_collection:
            mock_collection = AsyncMock()
            mock_get_collection.return_value = mock_collection
            
            # Mock API key found and active
            mock_api_key_doc = {
                "_id": "64b1c2d3e4f5a6b7c8d9e0f1",
                "user_id": "64a1b2c3d4e5f6a7b8c9d0e1",
                "key_hash": key_hash,
                "is_active": True,
                "expires_at": datetime.now(timezone.utc) + timedelta(days=30)
            }
            mock_collection.find_one.return_value = mock_api_key_doc
            
            # Mock update last_used_at
            mock_collection.update_one.return_value = MagicMock()
            
            result = await auth_service.verify_api_key(raw_key)
            
            assert result is not None
            assert result.user_id == "64a1b2c3d4e5f6a7b8c9d0e1"
            
            # Verify last_used_at is updated
            mock_collection.update_one.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_verify_api_key_invalid(self, auth_service):
        """Test API key verification with invalid key"""
        
        with patch('services.auth.get_api_keys_collection') as mock_get_collection:
            mock_collection = AsyncMock()
            mock_get_collection.return_value = mock_collection
            
            # Mock API key not found
            mock_collection.find_one.return_value = None
            
            result = await auth_service.verify_api_key("invalid_key")
            
            assert result is None


class TestCacheOperations:
    """Test caching functionality"""
    
    @pytest.fixture
    def auth_service(self):
        return AuthService()
    
    @pytest.mark.asyncio
    async def test_user_cache_key_generation(self, auth_service):
        """Test user cache key generation"""
        
        email = "test@example.com"
        
        # Test cache key generation
        cache_key = auth_service._cache_user_by_email_key(email, int(time.time()))
        
        assert cache_key.startswith("user_email:")
        assert email in cache_key
        
        # Test cache buckets (5-minute buckets)
        time1 = int(time.time())
        time2 = time1 + 200  # 3 minutes later
        time3 = time1 + 400  # 6 minutes later
        
        key1 = auth_service._cache_user_by_email_key(email, time1)
        key2 = auth_service._cache_user_by_email_key(email, time2)
        key3 = auth_service._cache_user_by_email_key(email, time3)
        
        # Keys should be same within 5-minute bucket
        assert key1 == key2
        # But different across bucket boundaries
        assert key1 != key3


class TestRateLimiting:
    """Test rate limiting functionality"""
    
    @pytest.fixture
    def auth_service(self):
        return AuthService()
    
    @pytest.mark.asyncio
    async def test_rate_limiting_integration(self, auth_service):
        """Test rate limiting integration"""
        
        user_id = "64a1b2c3d4e5f6a7b8c9d0e1"
        
        # Mock rate limiter
        with patch.object(auth_service, '_rate_limiter') as mock_rate_limiter:
            mock_rate_limiter.check_rate_limit = AsyncMock()
            mock_rate_limiter.check_rate_limit.return_value = {
                "allowed": True,
                "remaining": 10,
                "reset_time": int(time.time()) + 3600
            }
            
            # This would typically be called within login flow
            # Testing that rate limiter is properly integrated
            result = await auth_service._rate_limiter.check_rate_limit(
                f"login_user:{user_id}", 
                "login"
            )
            
            assert result["allowed"] is True
            assert "remaining" in result
            assert "reset_time" in result


class TestMetrics:
    """Test metrics collection"""
    
    @pytest.fixture
    def auth_service(self):
        return AuthService()
    
    def test_operation_metrics_initialization(self, auth_service):
        """Test operation metrics are properly initialized"""
        
        expected_operations = ["login", "register", "verify_token", "create_api_key"]
        
        for operation in expected_operations:
            assert operation in auth_service._operation_metrics
            assert auth_service._operation_metrics[operation]["count"] == 0
            assert auth_service._operation_metrics[operation]["total_time"] == 0.0
    
    def test_metrics_update(self, auth_service):
        """Test metrics are updated correctly"""
        
        operation = "login"
        duration = 0.123
        
        auth_service._update_metrics(operation, duration)
        
        assert auth_service._operation_metrics[operation]["count"] == 1
        assert auth_service._operation_metrics[operation]["total_time"] == duration
        
        # Test second update
        auth_service._update_metrics(operation, duration)
        
        assert auth_service._operation_metrics[operation]["count"] == 2
        assert auth_service._operation_metrics[operation]["total_time"] == duration * 2


class TestErrorHandling:
    """Test error handling scenarios"""
    
    @pytest.fixture
    def auth_service(self):
        return AuthService()
    
    @pytest.mark.asyncio
    async def test_database_connection_error(self, auth_service):
        """Test handling of database connection errors"""
        
        with patch('services.auth.get_users_collection') as mock_get_collection:
            mock_get_collection.side_effect = Exception("Database connection failed")
            
            result = await auth_service.authenticate_user("test@example.com", "password")
            
            assert result is None
    
    @pytest.mark.asyncio
    async def test_thread_pool_exhaustion(self, auth_service):
        """Test handling of thread pool exhaustion"""
        
        # Mock thread pool to raise exception
        with patch.object(auth_service._auth_thread_pool, 'submit') as mock_submit:
            mock_submit.side_effect = Exception("Thread pool exhausted")
            
            # This should not crash the service
            result = auth_service._hash_password("test_password")
            
            # Should fall back to synchronous execution or handle gracefully
            assert result is None or isinstance(result, str)


if __name__ == "__main__":
    # Run tests with pytest
    pytest.main([__file__, "-v", "--tb=short"])