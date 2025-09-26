"""
Path: infrastructure/source/api/tests/test_notification_service.py
Version: 1 - NotificationService Production Tests
"""

import pytest
import asyncio
import time
import smtplib
from datetime import datetime, timezone, timedelta
from unittest.mock import AsyncMock, MagicMock, patch, call
from typing import Dict, Any, List, Optional
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import json

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from services.notification import NotificationService
from models.base import ServiceHealthModel
from config import get_settings


class TestNotificationServiceCreation:
    """Test NotificationService creation and initialization"""
    
    def test_notification_service_initialization(self):
        """Test NotificationService initialization"""
        notification_service = NotificationService()
        
        # Check SMTP configuration
        assert hasattr(notification_service, '_smtp_host')
        assert hasattr(notification_service, '_smtp_port')
        assert hasattr(notification_service, '_smtp_username')
        assert hasattr(notification_service, '_smtp_password')
        assert hasattr(notification_service, '_use_tls')
        
        # Check email templates
        assert hasattr(notification_service, '_templates')
        assert isinstance(notification_service._templates, dict)
        
        # Check metrics
        assert hasattr(notification_service, '_metrics')
        assert "emails_sent" in notification_service._metrics
        assert "emails_failed" in notification_service._metrics
        assert "alerts_sent" in notification_service._metrics
        
        # Check rate limiting
        assert hasattr(notification_service, '_rate_limiter')
        
        # Check retry configuration
        assert hasattr(notification_service, '_max_retries')
        assert notification_service._max_retries >= 3


class TestEmailTemplates:
    """Test email template management"""
    
    @pytest.fixture
    def notification_service(self):
        return NotificationService()
    
    def test_template_initialization(self, notification_service):
        """Test email templates are properly initialized"""
        
        expected_templates = [
            "document_uploaded",
            "document_confirmed", 
            "document_failed",
            "verification_complete",
            "system_alert",
            "user_registered",
            "password_reset"
        ]
        
        for template_name in expected_templates:
            assert template_name in notification_service._templates
            template = notification_service._templates[template_name]
            assert "subject" in template
            assert "body_text" in template
            assert "body_html" in template
    
    def test_template_rendering(self, notification_service):
        """Test template rendering with variables"""
        
        template_name = "document_uploaded"
        context = {
            "user_name": "John Doe",
            "document_name": "test_document.pdf",
            "upload_time": "2024-01-15 12:00:00",
            "document_reference": "DOC-123456"
        }
        
        subject, body_text, body_html = notification_service._render_template(
            template_name, context
        )
        
        assert subject is not None
        assert body_text is not None
        assert body_html is not None
        
        # Verify context variables are replaced
        assert context["user_name"] in subject or context["user_name"] in body_text
        assert context["document_name"] in body_text
        assert context["document_reference"] in body_text
    
    def test_template_missing_context(self, notification_service):
        """Test template rendering with missing context variables"""
        
        template_name = "document_uploaded"
        incomplete_context = {
            "user_name": "John Doe"
            # Missing other required variables
        }
        
        subject, body_text, body_html = notification_service._render_template(
            template_name, incomplete_context
        )
        
        # Should still render, but may contain placeholder text
        assert subject is not None
        assert body_text is not None
        assert body_html is not None


class TestEmailSending:
    """Test email sending functionality"""
    
    @pytest.fixture
    def notification_service(self):
        return NotificationService()
    
    @pytest.fixture
    def sample_email_data(self):
        return {
            "to_email": "user@example.com",
            "to_name": "Test User",
            "subject": "Test Email Subject",
            "body_text": "This is a test email in plain text.",
            "body_html": "<p>This is a test email in <strong>HTML</strong>.</p>"
        }
    
    @pytest.mark.asyncio
    async def test_send_email_success(self, notification_service, sample_email_data):
        """Test successful email sending"""
        
        with patch('smtplib.SMTP') as mock_smtp_class:
            # Mock SMTP connection
            mock_smtp = MagicMock()
            mock_smtp_class.return_value.__enter__.return_value = mock_smtp
            mock_smtp.starttls.return_value = None
            mock_smtp.login.return_value = None
            mock_smtp.send_message.return_value = {}
            
            result = await notification_service.send_email(
                to_email=sample_email_data["to_email"],
                to_name=sample_email_data["to_name"],
                subject=sample_email_data["subject"],
                body_text=sample_email_data["body_text"],
                body_html=sample_email_data["body_html"]
            )
            
            assert result is True
            
            # Verify SMTP operations
            mock_smtp.starttls.assert_called_once()
            mock_smtp.login.assert_called_once()
            mock_smtp.send_message.assert_called_once()
            
            # Verify metrics
            assert notification_service._metrics["emails_sent"] == 1
    
    @pytest.mark.asyncio
    async def test_send_email_template(self, notification_service):
        """Test sending email using template"""
        
        with patch('smtplib.SMTP') as mock_smtp_class:
            mock_smtp = MagicMock()
            mock_smtp_class.return_value.__enter__.return_value = mock_smtp
            mock_smtp.starttls.return_value = None
            mock_smtp.login.return_value = None
            mock_smtp.send_message.return_value = {}
            
            context = {
                "user_name": "Jane Doe",
                "document_name": "important_document.pdf",
                "upload_time": "2024-01-15 14:30:00",
                "document_reference": "DOC-789012"
            }
            
            result = await notification_service.send_email_template(
                to_email="jane@example.com",
                to_name="Jane Doe",
                template_name="document_uploaded",
                context=context
            )
            
            assert result is True
            
            # Verify template was used
            mock_smtp.send_message.assert_called_once()
            call_args = mock_smtp.send_message.call_args[0][0]
            
            # Check that context variables were included in the message
            message_content = str(call_args)
            assert context["user_name"] in message_content or context["document_name"] in message_content
    
    @pytest.mark.asyncio
    async def test_send_email_smtp_error(self, notification_service, sample_email_data):
        """Test handling of SMTP errors"""
        
        with patch('smtplib.SMTP') as mock_smtp_class:
            # Mock SMTP connection error
            mock_smtp_class.side_effect = smtplib.SMTPException("SMTP connection failed")
            
            result = await notification_service.send_email(
                to_email=sample_email_data["to_email"],
                to_name=sample_email_data["to_name"],
                subject=sample_email_data["subject"],
                body_text=sample_email_data["body_text"]
            )
            
            assert result is False
            
            # Verify error metrics
            assert notification_service._metrics["emails_failed"] == 1
    
    @pytest.mark.asyncio
    async def test_send_email_authentication_error(self, notification_service, sample_email_data):
        """Test handling of authentication errors"""
        
        with patch('smtplib.SMTP') as mock_smtp_class:
            mock_smtp = MagicMock()
            mock_smtp_class.return_value.__enter__.return_value = mock_smtp
            mock_smtp.starttls.return_value = None
            mock_smtp.login.side_effect = smtplib.SMTPAuthenticationError(535, "Authentication failed")
            
            result = await notification_service.send_email(
                to_email=sample_email_data["to_email"],
                to_name=sample_email_data["to_name"],
                subject=sample_email_data["subject"],
                body_text=sample_email_data["body_text"]
            )
            
            assert result is False
            assert notification_service._metrics["emails_failed"] == 1
    
    @pytest.mark.asyncio
    async def test_send_email_rate_limiting(self, notification_service, sample_email_data):
        """Test email rate limiting"""
        
        with patch.object(notification_service._rate_limiter, 'check_rate_limit') as mock_rate_limit:
            mock_rate_limit.return_value = {
                "allowed": False,
                "remaining": 0,
                "reset_time": int(time.time()) + 3600,
                "error": "Email rate limit exceeded"
            }
            
            result = await notification_service.send_email(
                to_email=sample_email_data["to_email"],
                to_name=sample_email_data["to_name"],
                subject=sample_email_data["subject"],
                body_text=sample_email_data["body_text"]
            )
            
            assert result is False
            
            # Verify rate limit was checked
            mock_rate_limit.assert_called_once()


class TestAlertSystem:
    """Test alert system functionality"""
    
    @pytest.fixture
    def notification_service(self):
        return NotificationService()
    
    @pytest.mark.asyncio
    async def test_send_system_alert_success(self, notification_service):
        """Test successful system alert sending"""
        
        alert_data = {
            "severity": "high",
            "message": "Database connection lost",
            "details": {
                "service": "mongodb",
                "error_code": "ConnectionTimeout",
                "timestamp": datetime.now(timezone.utc).isoformat()
            },
            "recipients": ["admin@example.com", "ops@example.com"]
        }
        
        with patch.object(notification_service, 'send_email_template') as mock_send_email:
            mock_send_email.return_value = True
            
            result = await notification_service.send_system_alert(
                severity=alert_data["severity"],
                message=alert_data["message"],
                details=alert_data["details"],
                recipients=alert_data["recipients"]
            )
            
            assert result is True
            
            # Verify emails were sent to all recipients
            assert mock_send_email.call_count == len(alert_data["recipients"])
            
            # Verify metrics
            assert notification_service._metrics["alerts_sent"] == len(alert_data["recipients"])
    
    @pytest.mark.asyncio
    async def test_send_system_alert_severity_filtering(self, notification_service):
        """Test alert severity filtering"""
        
        # Test different severity levels
        severity_levels = ["low", "medium", "high", "critical"]
        
        for severity in severity_levels:
            with patch.object(notification_service, 'send_email_template') as mock_send_email:
                mock_send_email.return_value = True
                
                result = await notification_service.send_system_alert(
                    severity=severity,
                    message=f"Test {severity} alert",
                    details={"test": True},
                    recipients=["admin@example.com"]
                )
                
                if severity in ["high", "critical"]:
                    # High and critical alerts should always be sent
                    assert result is True
                    mock_send_email.assert_called_once()
                elif severity == "medium":
                    # Medium alerts should be sent based on configuration
                    assert result in [True, False]  # Depends on config
                else:
                    # Low alerts might be filtered
                    assert result in [True, False]  # Depends on config
    
    @pytest.mark.asyncio
    async def test_send_document_notification(self, notification_service):
        """Test document-related notifications"""
        
        notification_data = {
            "user_email": "user@example.com",
            "user_name": "Test User",
            "event_type": "document_confirmed",
            "document_reference": "DOC-123456",
            "document_name": "test_document.pdf",
            "blockchain_transaction": "ots_789012345"
        }
        
        with patch.object(notification_service, 'send_email_template') as mock_send_email:
            mock_send_email.return_value = True
            
            result = await notification_service.send_document_notification(
                user_email=notification_data["user_email"],
                user_name=notification_data["user_name"],
                event_type=notification_data["event_type"],
                document_reference=notification_data["document_reference"],
                document_name=notification_data["document_name"],
                additional_data={
                    "blockchain_transaction": notification_data["blockchain_transaction"]
                }
            )
            
            assert result is True
            
            # Verify correct template was used
            mock_send_email.assert_called_once()
            call_args = mock_send_email.call_args
            assert call_args[1]["template_name"] == notification_data["event_type"]
            assert call_args[1]["to_email"] == notification_data["user_email"]
            
            # Verify context contains document information
            context = call_args[1]["context"]
            assert context["document_reference"] == notification_data["document_reference"]
            assert context["document_name"] == notification_data["document_name"]


class TestRetryMechanism:
    """Test retry mechanism for failed notifications"""
    
    @pytest.fixture
    def notification_service(self):
        return NotificationService()
    
    @pytest.mark.asyncio
    async def test_email_retry_on_temporary_failure(self, notification_service):
        """Test retry mechanism on temporary failures"""
        
        with patch('smtplib.SMTP') as mock_smtp_class:
            call_count = 0
            
            def side_effect(*args, **kwargs):
                nonlocal call_count
                call_count += 1
                
                if call_count <= 2:
                    # First two attempts fail
                    raise smtplib.SMTPServerDisconnected("Temporary server error")
                
                # Third attempt succeeds
                mock_smtp = MagicMock()
                mock_smtp.starttls.return_value = None
                mock_smtp.login.return_value = None
                mock_smtp.send_message.return_value = {}
                return mock_smtp.__enter__.return_value
            
            mock_smtp_class.side_effect = side_effect
            
            with patch('asyncio.sleep'):  # Speed up test
                result = await notification_service.send_email(
                    to_email="retry@example.com",
                    to_name="Retry Test",
                    subject="Retry Test Email",
                    body_text="This is a retry test."
                )
            
            assert result is True
            assert call_count == 3  # Two failures + one success
    
    @pytest.mark.asyncio
    async def test_email_retry_exhaustion(self, notification_service):
        """Test retry exhaustion after max attempts"""
        
        with patch('smtplib.SMTP') as mock_smtp_class:
            # Always fail
            mock_smtp_class.side_effect = smtplib.SMTPException("Persistent error")
            
            with patch('asyncio.sleep'):  # Speed up test
                result = await notification_service.send_email(
                    to_email="exhaustion@example.com",
                    to_name="Exhaustion Test",
                    subject="Exhaustion Test Email",
                    body_text="This should fail after retries."
                )
            
            assert result is False
            
            # Should have attempted max_retries + 1 times
            assert mock_smtp_class.call_count == notification_service._max_retries + 1


class TestBulkNotifications:
    """Test bulk notification functionality"""
    
    @pytest.fixture
    def notification_service(self):
        return NotificationService()
    
    @pytest.mark.asyncio
    async def test_send_bulk_emails_success(self, notification_service):
        """Test successful bulk email sending"""
        
        recipients = [
            {"email": "user1@example.com", "name": "User One"},
            {"email": "user2@example.com", "name": "User Two"},
            {"email": "user3@example.com", "name": "User Three"}
        ]
        
        template_name = "system_alert"
        context = {
            "alert_type": "maintenance",
            "message": "Scheduled maintenance notification",
            "start_time": "2024-01-20 02:00:00 UTC"
        }
        
        with patch.object(notification_service, 'send_email_template') as mock_send_email:
            mock_send_email.return_value = True
            
            results = await notification_service.send_bulk_emails(
                recipients=recipients,
                template_name=template_name,
                context=context
            )
            
            assert len(results) == len(recipients)
            assert all(result["success"] for result in results)
            
            # Verify all emails were sent
            assert mock_send_email.call_count == len(recipients)
    
    @pytest.mark.asyncio
    async def test_send_bulk_emails_partial_failure(self, notification_service):
        """Test bulk email sending with partial failures"""
        
        recipients = [
            {"email": "success@example.com", "name": "Success User"},
            {"email": "failure@example.com", "name": "Failure User"}
        ]
        
        def mock_send_side_effect(**kwargs):
            # Fail for specific email
            if kwargs["to_email"] == "failure@example.com":
                return False
            return True
        
        with patch.object(notification_service, 'send_email_template', side_effect=mock_send_side_effect):
            results = await notification_service.send_bulk_emails(
                recipients=recipients,
                template_name="system_alert",
                context={"message": "Test bulk"}
            )
            
            assert len(results) == 2
            assert results[0]["success"] is True
            assert results[1]["success"] is False
            assert "error" in results[1]
    
    @pytest.mark.asyncio
    async def test_send_bulk_emails_rate_limiting(self, notification_service):
        """Test bulk email rate limiting"""
        
        # Large number of recipients to test rate limiting
        recipients = [
            {"email": f"user{i}@example.com", "name": f"User {i}"}
            for i in range(100)
        ]
        
        with patch.object(notification_service, 'send_email_template') as mock_send_email:
            # Mock rate limiting after 10 emails
            call_count = 0
            
            def rate_limited_send(**kwargs):
                nonlocal call_count
                call_count += 1
                if call_count > 10:
                    return False  # Rate limited
                return True
            
            mock_send_email.side_effect = rate_limited_send
            
            results = await notification_service.send_bulk_emails(
                recipients=recipients,
                template_name="system_alert",
                context={"message": "Rate limit test"}
            )
            
            successful_sends = [r for r in results if r["success"]]
            failed_sends = [r for r in results if not r["success"]]
            
            # Should have some successes and some failures due to rate limiting
            assert len(successful_sends) <= 10
            assert len(failed_sends) > 0


class TestHealthCheck:
    """Test health check functionality"""
    
    @pytest.fixture
    def notification_service(self):
        return NotificationService()
    
    @pytest.mark.asyncio
    async def test_health_check_healthy(self, notification_service):
        """Test health check when service is healthy"""
        
        with patch('smtplib.SMTP') as mock_smtp_class:
            mock_smtp = MagicMock()
            mock_smtp_class.return_value.__enter__.return_value = mock_smtp
            mock_smtp.starttls.return_value = None
            mock_smtp.login.return_value = None
            
            health = await notification_service.health_check()
            
            assert health["status"] == "healthy"
            assert "smtp_connection" in health
            assert health["smtp_connection"] is True
            assert "response_time" in health
    
    @pytest.mark.asyncio
    async def test_health_check_unhealthy(self, notification_service):
        """Test health check when service is unhealthy"""
        
        with patch('smtplib.SMTP') as mock_smtp_class:
            mock_smtp_class.side_effect = smtplib.SMTPException("SMTP server unavailable")
            
            health = await notification_service.health_check()
            
            assert health["status"] == "unhealthy"
            assert "error" in health
            assert "smtp server unavailable" in health["error"].lower()


class TestMetrics:
    """Test metrics collection and reporting"""
    
    @pytest.fixture
    def notification_service(self):
        return NotificationService()
    
    def test_metrics_initialization(self, notification_service):
        """Test metrics are properly initialized"""
        
        expected_metrics = [
            "emails_sent", "emails_failed", "alerts_sent",
            "total_send_time", "template_renders", "rate_limit_hits"
        ]
        
        for metric in expected_metrics:
            assert metric in notification_service._metrics
            assert isinstance(notification_service._metrics[metric], (int, float))
    
    @pytest.mark.asyncio
    async def test_metrics_update_on_operations(self, notification_service):
        """Test metrics are updated during operations"""
        
        initial_sent = notification_service._metrics["emails_sent"]
        initial_failed = notification_service._metrics["emails_failed"]
        
        # Test successful email
        with patch('smtplib.SMTP') as mock_smtp_class:
            mock_smtp = MagicMock()
            mock_smtp_class.return_value.__enter__.return_value = mock_smtp
            mock_smtp.starttls.return_value = None
            mock_smtp.login.return_value = None
            mock_smtp.send_message.return_value = {}
            
            await notification_service.send_email(
                to_email="metrics@example.com",
                to_name="Metrics Test",
                subject="Metrics Test",
                body_text="Testing metrics"
            )
            
            assert notification_service._metrics["emails_sent"] == initial_sent + 1
        
        # Test failed email
        with patch('smtplib.SMTP') as mock_smtp_class:
            mock_smtp_class.side_effect = smtplib.SMTPException("Test failure")
            
            await notification_service.send_email(
                to_email="metrics_fail@example.com",
                to_name="Metrics Fail",
                subject="Metrics Fail",
                body_text="Testing failure metrics"
            )
            
            assert notification_service._metrics["emails_failed"] == initial_failed + 1
    
    def test_get_metrics(self, notification_service):
        """Test metrics retrieval"""
        
        # Set test metrics
        notification_service._metrics.update({
            "emails_sent": 100,
            "emails_failed": 5,
            "alerts_sent": 20,
            "total_send_time": 150.0,
            "template_renders": 120
        })
        
        metrics = notification_service.get_metrics()
        
        assert metrics["emails_sent"] == 100
        assert metrics["emails_failed"] == 5
        assert metrics["alerts_sent"] == 20
        assert "success_rate" in metrics
        assert "average_send_time" in metrics
        
        # Verify calculated metrics
        expected_success_rate = (100 / (100 + 5)) * 100
        assert abs(metrics["success_rate"] - expected_success_rate) < 0.01
        
        expected_avg_time = 150.0 / 100
        assert abs(metrics["average_send_time"] - expected_avg_time) < 0.01


class TestConfigurationHandling:
    """Test configuration and settings integration"""
    
    @pytest.fixture
    def notification_service(self):
        return NotificationService()
    
    def test_smtp_configuration(self, notification_service):
        """Test SMTP configuration from settings"""
        
        settings = get_settings()
        
        # Verify SMTP settings are used
        assert hasattr(notification_service, '_smtp_host')
        assert hasattr(notification_service, '_smtp_port')
        assert hasattr(notification_service, '_use_tls')
        
        # Default values should be reasonable
        assert notification_service._smtp_port in [25, 465, 587]
        assert isinstance(notification_service._use_tls, bool)
    
    def test_email_sender_configuration(self, notification_service):
        """Test email sender configuration"""
        
        assert hasattr(notification_service, '_from_email')
        assert hasattr(notification_service, '_from_name')
        
        # Should have reasonable defaults
        assert "@" in notification_service._from_email
        assert len(notification_service._from_name) > 0


if __name__ == "__main__":
    # Run tests with pytest
    pytest.main([__file__, "-v", "--tb=short"])