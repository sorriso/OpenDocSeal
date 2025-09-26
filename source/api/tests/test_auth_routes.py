"""
Path: infrastructure/source/api/tests/test_auth_routes.py
Version: 1 - Auth Routes End-to-End Tests
"""

import pytest
import json
from datetime import datetime, timezone, timedelta
from unittest.mock import AsyncMock, MagicMock, patch
from typing import Dict, Any

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi.testclient import TestClient
from fastapi import status

# Import the FastAPI app
from main import app
from models.auth import UserCreate, LoginRequest, TokenResponse, User, UserResponse
from models.base import UserRole, ResponseModel


class TestAuthRoutesSetup:
    """Test auth routes setup and configuration"""
    
    @pytest.fixture
    def client(self):
        """Create test client"""
        return TestClient(app)
    
    @pytest.fixture
    def mock_auth_service(self):
        """Mock auth service for testing"""
        return AsyncMock()
    
    @pytest.fixture
    def sample_user_data(self):
        """Sample user data for testing"""
        return {
            "email": "test@example.com",
            "name": "Test User",
            "password": "SecurePassword123!",
            "role": "user"
        }
    
    @pytest.fixture
    def sample_login_data(self):
        """Sample login data for testing"""
        return {
            "email": "test@example.com",
            "password": "SecurePassword123!"
        }
    
    @pytest.fixture
    def mock_user(self):
        """Mock user object"""
        return User(
            id="user_123",
            email="test@example.com",
            name="Test User",
            role=UserRole.USER,
            is_active=True,
            email_verified=True,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
            last_login=None
        )
    
    @pytest.fixture
    def mock_token_response(self):
        """Mock token response"""
        return TokenResponse(
            access_token="eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.test_token",
            refresh_token="refresh_token_123",
            token_type="bearer",
            expires_in=1800,
            user={
                "id": "user_123",
                "email": "test@example.com",
                "name": "Test User",
                "role": "user",
                "is_active": True
            }
        )


class TestUserRegistration:
    """Test user registration endpoint"""
    
    def test_register_user_success(self, client, sample_user_data, mock_user):
        """Test successful user registration"""
        
        with patch('routes.auth.get_auth_service') as mock_get_service, \
             patch('routes.auth.log_audit_event') as mock_audit, \
             patch('routes.auth.get_correlation_id') as mock_correlation:
            
            # Setup mocks
            mock_auth_service = AsyncMock()
            mock_get_service.return_value = mock_auth_service
            mock_auth_service.create_user.return_value = mock_user
            mock_correlation.return_value = "test-correlation-123"
            
            # Make request
            response = client.post(
                "/api/v1/auth/register",
                json=sample_user_data,
                headers={"Content-Type": "application/json"}
            )
            
            # Verify response
            assert response.status_code == status.HTTP_201_CREATED
            
            response_data = response.json()
            assert response_data["id"] == "user_123"
            assert response_data["email"] == "test@example.com"
            assert response_data["name"] == "Test User"
            assert response_data["role"] == "user"
            assert response_data["is_active"] is True
            
            # Verify service was called correctly
            mock_auth_service.create_user.assert_called_once()
            call_args = mock_auth_service.create_user.call_args[0][0]
            assert call_args.email == "test@example.com"
            assert call_args.name == "Test User"
            assert call_args.password == "SecurePassword123!"
    
    def test_register_user_validation_error(self, client):
        """Test user registration with validation error"""
        
        invalid_data = {
            "email": "invalid-email",
            "name": "",
            "password": "weak"
        }
        
        response = client.post(
            "/api/v1/auth/register",
            json=invalid_data,
            headers={"Content-Type": "application/json"}
        )
        
        # Should return validation error
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
    
    def test_register_user_duplicate_email(self, client, sample_user_data):
        """Test user registration with duplicate email"""
        
        with patch('routes.auth.get_auth_service') as mock_get_service, \
             patch('routes.auth.get_correlation_id') as mock_correlation:
            
            mock_auth_service = AsyncMock()
            mock_get_service.return_value = mock_auth_service
            mock_auth_service.create_user.side_effect = ValueError("User with this email already exists")
            mock_correlation.return_value = "test-correlation-123"
            
            response = client.post(
                "/api/v1/auth/register",
                json=sample_user_data,
                headers={"Content-Type": "application/json"}
            )
            
            assert response.status_code == status.HTTP_400_BAD_REQUEST
            assert "User with this email already exists" in response.json()["detail"]


class TestUserLogin:
    """Test user login endpoint"""
    
    def test_login_user_success(self, client, sample_login_data, mock_token_response):
        """Test successful user login"""
        
        with patch('routes.auth.get_auth_service') as mock_get_service, \
             patch('routes.auth.get_settings') as mock_settings, \
             patch('routes.auth.log_audit_event') as mock_audit, \
             patch('routes.auth.get_correlation_id') as mock_correlation:
            
            # Setup mocks
            mock_auth_service = AsyncMock()
            mock_get_service.return_value = mock_auth_service
            mock_auth_service.authenticate_user.return_value = mock_token_response
            
            mock_settings_obj = MagicMock()
            mock_settings_obj.sso_enabled = False  # Disable SSO for this test
            mock_settings.return_value = mock_settings_obj
            
            mock_correlation.return_value = "test-correlation-123"
            
            # Make request
            response = client.post(
                "/api/v1/auth/login",
                json=sample_login_data,
                headers={"Content-Type": "application/json"}
            )
            
            # Verify response
            assert response.status_code == status.HTTP_200_OK
            
            response_data = response.json()
            assert response_data["access_token"] == mock_token_response.access_token
            assert response_data["refresh_token"] == mock_token_response.refresh_token
            assert response_data["token_type"] == "bearer"
            assert response_data["expires_in"] == 1800
            assert response_data["user"]["id"] == "user_123"
            
            # Verify service was called with LoginRequest object
            mock_auth_service.authenticate_user.assert_called_once()
            call_args = mock_auth_service.authenticate_user.call_args
            assert call_args[1]["login_request"].email == "test@example.com"
            assert call_args[1]["login_request"].password == "SecurePassword123!"
    
    def test_login_user_invalid_credentials(self, client, sample_login_data):
        """Test login with invalid credentials"""
        
        with patch('routes.auth.get_auth_service') as mock_get_service, \
             patch('routes.auth.get_settings') as mock_settings, \
             patch('routes.auth.get_correlation_id') as mock_correlation:
            
            mock_auth_service = AsyncMock()
            mock_get_service.return_value = mock_auth_service
            mock_auth_service.authenticate_user.return_value = None  # Invalid credentials
            
            mock_settings_obj = MagicMock()
            mock_settings_obj.sso_enabled = False
            mock_settings.return_value = mock_settings_obj
            
            mock_correlation.return_value = "test-correlation-123"
            
            response = client.post(
                "/api/v1/auth/login",
                json=sample_login_data,
                headers={"Content-Type": "application/json"}
            )
            
            assert response.status_code == status.HTTP_401_UNAUTHORIZED
            assert response.json()["detail"] == "Invalid credentials"
    
    def test_login_sso_mode_rejection(self, client, sample_login_data):
        """Test login rejection when SSO is enabled"""
        
        with patch('routes.auth.get_settings') as mock_settings, \
             patch('routes.auth.get_correlation_id') as mock_correlation:
            
            mock_settings_obj = MagicMock()
            mock_settings_obj.sso_enabled = True  # Enable SSO
            mock_settings.return_value = mock_settings_obj
            
            mock_correlation.return_value = "test-correlation-123"
            
            response = client.post(
                "/api/v1/auth/login",
                json=sample_login_data,
                headers={"Content-Type": "application/json"}
            )
            
            assert response.status_code == status.HTTP_400_BAD_REQUEST
            assert "Login not available in SSO mode" in response.json()["detail"]


class TestTokenRefresh:
    """Test token refresh endpoint"""
    
    def test_refresh_token_success(self, client, mock_token_response):
        """Test successful token refresh"""
        
        refresh_data = {"refresh_token": "valid_refresh_token_123"}
        
        with patch('routes.auth.get_auth_service') as mock_get_service, \
             patch('routes.auth.get_settings') as mock_settings, \
             patch('routes.auth.log_audit_event') as mock_audit, \
             patch('routes.auth.get_correlation_id') as mock_correlation:
            
            mock_auth_service = AsyncMock()
            mock_get_service.return_value = mock_auth_service
            mock_auth_service.refresh_token.return_value = mock_token_response
            
            mock_settings_obj = MagicMock()
            mock_settings_obj.sso_enabled = False
            mock_settings.return_value = mock_settings_obj
            
            mock_correlation.return_value = "test-correlation-123"
            
            response = client.post(
                "/api/v1/auth/refresh",
                json=refresh_data,
                headers={"Content-Type": "application/json"}
            )
            
            assert response.status_code == status.HTTP_200_OK
            
            response_data = response.json()
            assert response_data["access_token"] == mock_token_response.access_token
            assert response_data["refresh_token"] == mock_token_response.refresh_token
            
            # Verify service was called with correct refresh token
            mock_auth_service.refresh_token.assert_called_once_with("valid_refresh_token_123")
    
    def test_refresh_token_invalid(self, client):
        """Test token refresh with invalid refresh token"""
        
        refresh_data = {"refresh_token": "invalid_refresh_token"}
        
        with patch('routes.auth.get_auth_service') as mock_get_service, \
             patch('routes.auth.get_settings') as mock_settings, \
             patch('routes.auth.get_correlation_id') as mock_correlation:
            
            mock_auth_service = AsyncMock()
            mock_get_service.return_value = mock_auth_service
            mock_auth_service.refresh_token.return_value = None  # Invalid token
            
            mock_settings_obj = MagicMock()
            mock_settings_obj.sso_enabled = False
            mock_settings.return_value = mock_settings_obj
            
            mock_correlation.return_value = "test-correlation-123"
            
            response = client.post(
                "/api/v1/auth/refresh",
                json=refresh_data,
                headers={"Content-Type": "application/json"}
            )
            
            assert response.status_code == status.HTTP_401_UNAUTHORIZED
            assert "Invalid or expired refresh token" in response.json()["detail"]
    
    def test_refresh_token_sso_mode_rejection(self, client):
        """Test token refresh rejection when SSO is enabled"""
        
        refresh_data = {"refresh_token": "any_token"}
        
        with patch('routes.auth.get_settings') as mock_settings, \
             patch('routes.auth.get_correlation_id') as mock_correlation:
            
            mock_settings_obj = MagicMock()
            mock_settings_obj.sso_enabled = True
            mock_settings.return_value = mock_settings_obj
            
            mock_correlation.return_value = "test-correlation-123"
            
            response = client.post(
                "/api/v1/auth/refresh",
                json=refresh_data,
                headers={"Content-Type": "application/json"}
            )
            
            assert response.status_code == status.HTTP_400_BAD_REQUEST
            assert "Token refresh not available in SSO mode" in response.json()["detail"]


class TestUserLogout:
    """Test user logout endpoint"""
    
    def test_logout_success_with_blacklist(self, client, mock_user):
        """Test successful logout with token blacklisting"""
        
        with patch('routes.auth.get_current_active_user') as mock_get_user, \
             patch('routes.auth.get_settings') as mock_settings, \
             patch('routes.auth.verify_token') as mock_verify, \
             patch('routes.auth.blacklist_token') as mock_blacklist, \
             patch('routes.auth.log_audit_event') as mock_audit, \
             patch('routes.auth.get_correlation_id') as mock_correlation:
            
            # Setup mocks
            mock_get_user.return_value = mock_user
            
            mock_settings_obj = MagicMock()
            mock_settings_obj.jwt_blacklist_enabled = True
            mock_settings.return_value = mock_settings_obj
            
            mock_verify.return_value = {
                "jti": "token_id_123",
                "exp": (datetime.now(timezone.utc) + timedelta(hours=1)).timestamp()
            }
            
            mock_correlation.return_value = "test-correlation-123"
            
            # Make request with Bearer token
            response = client.post(
                "/api/v1/auth/logout",
                headers={
                    "Authorization": "Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.test_token",
                    "Content-Type": "application/json"
                }
            )
            
            assert response.status_code == status.HTTP_200_OK
            
            response_data = response.json()
            assert response_data["success"] is True
            assert response_data["message"] == "Logout successful"
            
            # Verify token was blacklisted
            mock_verify.assert_called_once()
            mock_blacklist.assert_called_once()
    
    def test_logout_without_blacklist(self, client, mock_user):
        """Test logout when blacklisting is disabled"""
        
        with patch('routes.auth.get_current_active_user') as mock_get_user, \
             patch('routes.auth.get_settings') as mock_settings, \
             patch('routes.auth.log_audit_event') as mock_audit, \
             patch('routes.auth.get_correlation_id') as mock_correlation:
            
            mock_get_user.return_value = mock_user
            
            mock_settings_obj = MagicMock()
            mock_settings_obj.jwt_blacklist_enabled = False
            mock_settings.return_value = mock_settings_obj
            
            mock_correlation.return_value = "test-correlation-123"
            
            response = client.post(
                "/api/v1/auth/logout",
                headers={
                    "Authorization": "Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.test_token",
                    "Content-Type": "application/json"
                }
            )
            
            assert response.status_code == status.HTTP_200_OK
            assert response.json()["success"] is True
    
    def test_logout_unauthorized(self, client):
        """Test logout without authentication"""
        
        response = client.post(
            "/api/v1/auth/logout",
            headers={"Content-Type": "application/json"}
        )
        
        assert response.status_code == status.HTTP_403_FORBIDDEN


class TestSSO:
    """Test SSO-related endpoints"""
    
    def test_sso_status_enabled(self, client):
        """Test SSO status when SSO is enabled"""
        
        with patch('routes.auth.get_settings') as mock_settings, \
             patch('routes.auth.get_correlation_id') as mock_correlation:
            
            mock_settings_obj = MagicMock()
            mock_settings_obj.sso_enabled = True
            mock_settings_obj.behind_reverse_proxy = True
            mock_settings.return_value = mock_settings_obj
            
            mock_correlation.return_value = "test-correlation-123"
            
            response = client.get(
                "/api/v1/auth/sso/status",
                headers={
                    "X-Remote-User": "test_user",
                    "X-Remote-Name": "Test User",
                    "X-Remote-Email": "test@example.com"
                }
            )
            
            assert response.status_code == status.HTTP_200_OK
            
            response_data = response.json()
            assert response_data["success"] is True
            assert response_data["data"]["enabled"] is True
            assert response_data["data"]["behind_proxy"] is True
            assert response_data["data"]["headers_present"] is True
            assert len(response_data["data"]["headers_required"]) == 3
    
    def test_sso_status_disabled(self, client):
        """Test SSO status when SSO is disabled"""
        
        with patch('routes.auth.get_settings') as mock_settings, \
             patch('routes.auth.get_correlation_id') as mock_correlation:
            
            mock_settings_obj = MagicMock()
            mock_settings_obj.sso_enabled = False
            mock_settings_obj.behind_reverse_proxy = False
            mock_settings.return_value = mock_settings_obj
            
            mock_correlation.return_value = "test-correlation-123"
            
            response = client.get("/api/v1/auth/sso/status")
            
            assert response.status_code == status.HTTP_200_OK
            
            response_data = response.json()
            assert response_data["data"]["enabled"] is False
            assert response_data["data"]["headers_required"] == []


class TestUserProfile:
    """Test user profile endpoints"""
    
    def test_get_user_profile_success(self, client, mock_user):
        """Test successful profile retrieval"""
        
        with patch('routes.auth.get_current_active_user') as mock_get_user, \
             patch('routes.auth.get_correlation_id') as mock_correlation:
            
            mock_get_user.return_value = mock_user
            mock_correlation.return_value = "test-correlation-123"
            
            response = client.get(
                "/api/v1/auth/profile",
                headers={"Authorization": "Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.test_token"}
            )
            
            assert response.status_code == status.HTTP_200_OK
            
            response_data = response.json()
            assert response_data["id"] == "user_123"
            assert response_data["email"] == "test@example.com"
            assert response_data["name"] == "Test User"
            assert response_data["role"] == "user"
    
    def test_update_user_profile_success(self, client, mock_user):
        """Test successful profile update"""
        
        update_data = {
            "name": "Updated Test User",
            "organization": "Test Company"
        }
        
        updated_user = User(
            id="user_123",
            email="test@example.com",
            name="Updated Test User",
            role=UserRole.USER,
            is_active=True,
            email_verified=True,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
            last_login=None
        )
        
        with patch('routes.auth.get_current_active_user') as mock_get_user, \
             patch('routes.auth.get_auth_service') as mock_get_service, \
             patch('routes.auth.log_audit_event') as mock_audit, \
             patch('routes.auth.get_correlation_id') as mock_correlation:
            
            mock_get_user.return_value = mock_user
            
            mock_auth_service = AsyncMock()
            mock_get_service.return_value = mock_auth_service
            mock_auth_service.update_user.return_value = updated_user
            
            mock_correlation.return_value = "test-correlation-123"
            
            response = client.put(
                "/api/v1/auth/profile",
                json=update_data,
                headers={
                    "Authorization": "Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.test_token",
                    "Content-Type": "application/json"
                }
            )
            
            assert response.status_code == status.HTTP_200_OK
            
            response_data = response.json()
            assert response_data["name"] == "Updated Test User"
            
            # Verify service was called
            mock_auth_service.update_user.assert_called_once()


class TestPasswordChange:
    """Test password change endpoint"""
    
    def test_change_password_success(self, client, mock_user):
        """Test successful password change"""
        
        password_data = {
            "current_password": "OldPassword123!",
            "new_password": "NewPassword123!",
            "confirm_password": "NewPassword123!"
        }
        
        with patch('routes.auth.get_current_active_user') as mock_get_user, \
             patch('routes.auth.get_auth_service') as mock_get_service, \
             patch('routes.auth.log_audit_event') as mock_audit, \
             patch('routes.auth.get_correlation_id') as mock_correlation:
            
            mock_get_user.return_value = mock_user
            
            mock_auth_service = AsyncMock()
            mock_get_service.return_value = mock_auth_service
            mock_auth_service.change_password.return_value = True
            
            mock_correlation.return_value = "test-correlation-123"
            
            response = client.post(
                "/api/v1/auth/change-password",
                json=password_data,
                headers={
                    "Authorization": "Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.test_token",
                    "Content-Type": "application/json"
                }
            )
            
            assert response.status_code == status.HTTP_200_OK
            
            response_data = response.json()
            assert response_data["success"] is True
            assert response_data["message"] == "Password changed successfully"
            
            # Verify service was called
            mock_auth_service.change_password.assert_called_once()
    
    def test_change_password_failure(self, client, mock_user):
        """Test password change failure"""
        
        password_data = {
            "current_password": "WrongPassword123!",
            "new_password": "NewPassword123!",
            "confirm_password": "NewPassword123!"
        }
        
        with patch('routes.auth.get_current_active_user') as mock_get_user, \
             patch('routes.auth.get_auth_service') as mock_get_service, \
             patch('routes.auth.get_correlation_id') as mock_correlation:
            
            mock_get_user.return_value = mock_user
            
            mock_auth_service = AsyncMock()
            mock_get_service.return_value = mock_auth_service
            mock_auth_service.change_password.return_value = False
            
            mock_correlation.return_value = "test-correlation-123"
            
            response = client.post(
                "/api/v1/auth/change-password",
                json=password_data,
                headers={
                    "Authorization": "Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.test_token",
                    "Content-Type": "application/json"
                }
            )
            
            assert response.status_code == status.HTTP_400_BAD_REQUEST
            assert "Password change failed" in response.json()["detail"]


if __name__ == "__main__":
    # Run tests with pytest
    pytest.main([__file__, "-v"])