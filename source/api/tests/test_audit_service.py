"""
Path: infrastructure/source/api/tests/test_audit_service.py
Version: 1 - AuditService Production Tests
"""

import pytest
import asyncio
import time
from datetime import datetime, timezone, timedelta
from unittest.mock import AsyncMock, MagicMock, patch, call
from typing import Dict, Any, List, Optional
import json

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from services.audit import AuditService
from models.base import AuditAction, ServiceHealthModel
from config import get_settings
from database import get_audit_logs_collection


class TestAuditServiceCreation:
    """Test AuditService creation and initialization"""
    
    def test_audit_service_initialization(self):
        """Test AuditService initialization"""
        audit_service = AuditService()
        
        # Check batch processing configuration
        assert hasattr(audit_service, '_batch_size')
        assert audit_service._batch_size > 0
        assert audit_service._batch_size <= 1000
        
        # Check flush interval
        assert hasattr(audit_service, '_flush_interval')
        assert audit_service._flush_interval > 0
        
        # Check pending logs buffer
        assert hasattr(audit_service, '_pending_logs')
        assert isinstance(audit_service._pending_logs, list)
        
        # Check metrics
        assert hasattr(audit_service, '_metrics')
        assert "logs_recorded" in audit_service._metrics
        assert "logs_failed" in audit_service._metrics
        assert "batch_flushes" in audit_service._metrics
        
        # Check background task
        assert hasattr(audit_service, '_flush_task')
        
        # Check rate limiter
        assert hasattr(audit_service, '_rate_limiter')


class TestAuditLogCreation:
    """Test audit log creation and formatting"""
    
    @pytest.fixture
    def audit_service(self):
        return AuditService()
    
    def test_create_log_entry_basic(self, audit_service):
        """Test basic audit log entry creation"""
        
        log_entry = audit_service._create_log_entry(
            action=AuditAction.USER_LOGIN,
            user_id="user_123",
            details={"ip_address": "192.168.1.100"},
            correlation_id="corr_123"
        )
        
        assert log_entry is not None
        assert log_entry["action"] == AuditAction.USER_LOGIN.value
        assert log_entry["user_id"] == "user_123"
        assert log_entry["details"]["ip_address"] == "192.168.1.100"
        assert log_entry["correlation_id"] == "corr_123"
        assert "timestamp" in log_entry
        assert "event_id" in log_entry
        assert isinstance(log_entry["timestamp"], datetime)
    
    def test_create_log_entry_with_resource(self, audit_service):
        """Test audit log entry with resource information"""
        
        log_entry = audit_service._create_log_entry(
            action=AuditAction.DOCUMENT_CREATED,
            user_id="user_456",
            resource_type="document",
            resource_id="doc_789",
            details={
                "filename": "test_document.pdf",
                "size": 1024,
                "content_type": "application/pdf"
            }
        )
        
        assert log_entry["action"] == AuditAction.DOCUMENT_CREATED.value
        assert log_entry["resource_type"] == "document"
        assert log_entry["resource_id"] == "doc_789"
        assert log_entry["details"]["filename"] == "test_document.pdf"
        assert log_entry["details"]["size"] == 1024
    
    def test_create_log_entry_sensitive_data_masking(self, audit_service):
        """Test masking of sensitive data in audit logs"""
        
        sensitive_details = {
            "password": "secret123",
            "api_key": "sk_12345678901234567890",
            "email": "user@example.com",
            "user_agent": "Mozilla/5.0...",
            "session_token": "sess_abcdef123456"
        }
        
        log_entry = audit_service._create_log_entry(
            action=AuditAction.USER_REGISTER,
            user_id="user_new",
            details=sensitive_details
        )
        
        # Sensitive fields should be masked
        assert log_entry["details"]["password"] == "[MASKED]"
        assert log_entry["details"]["api_key"] == "[MASKED]"
        assert log_entry["details"]["session_token"] == "[MASKED]"
        
        # Non-sensitive fields should remain
        assert log_entry["details"]["email"] == "user@example.com"
        assert log_entry["details"]["user_agent"] == "Mozilla/5.0..."
    
    def test_create_log_entry_large_details(self, audit_service):
        """Test handling of large details objects"""
        
        # Create large details object
        large_details = {
            "large_data": "x" * 10000,  # 10KB string
            "metadata": {"key_" + str(i): f"value_{i}" for i in range(100)}
        }
        
        log_entry = audit_service._create_log_entry(
            action=AuditAction.DOCUMENT_UPLOADED,
            user_id="user_large",
            details=large_details
        )
        
        assert log_entry is not None
        
        # Details should be truncated or summarized for large objects
        details_str = json.dumps(log_entry["details"])
        assert len(details_str) < 5000  # Should be truncated


class TestBatchProcessing:
    """Test batch processing functionality"""
    
    @pytest.fixture
    def audit_service(self):
        service = AuditService()
        service._batch_size = 5  # Small batch size for testing
        return service
    
    @pytest.mark.asyncio
    async def test_log_audit_event_batching(self, audit_service):
        """Test audit event batching"""
        
        with patch('services.audit.get_audit_logs_collection') as mock_get_collection:
            mock_collection = AsyncMock()
            mock_get_collection.return_value = mock_collection
            mock_collection.insert_many.return_value = MagicMock(
                inserted_ids=["id1", "id2", "id3", "id4", "id5"]
            )
            
            # Add logs one by one (should not flush until batch is full)
            for i in range(4):
                await audit_service.log_audit_event(
                    action=AuditAction.USER_LOGIN,
                    user_id=f"user_{i}",
                    details={"attempt": i}
                )
                
                # Should not have flushed yet
                assert len(audit_service._pending_logs) == i + 1
                mock_collection.insert_many.assert_not_called()
            
            # Fifth log should trigger batch flush
            await audit_service.log_audit_event(
                action=AuditAction.USER_LOGIN,
                user_id="user_5",
                details={"attempt": 5}
            )
            
            # Should have flushed the batch
            mock_collection.insert_many.assert_called_once()
            assert len(audit_service._pending_logs) == 0
            assert audit_service._metrics["batch_flushes"] == 1
            assert audit_service._metrics["logs_recorded"] == 5
    
    @pytest.mark.asyncio
    async def test_manual_flush(self, audit_service):
        """Test manual flush of pending logs"""
        
        with patch('services.audit.get_audit_logs_collection') as mock_get_collection:
            mock_collection = AsyncMock()
            mock_get_collection.return_value = mock_collection
            mock_collection.insert_many.return_value = MagicMock(
                inserted_ids=["id1", "id2", "id3"]
            )
            
            # Add some logs (less than batch size)
            for i in range(3):
                await audit_service.log_audit_event(
                    action=AuditAction.DOCUMENT_ACCESSED,
                    user_id=f"user_{i}",
                    details={"doc_id": f"doc_{i}"}
                )
            
            assert len(audit_service._pending_logs) == 3
            
            # Manual flush
            await audit_service.flush_pending_logs()
            
            # Should have flushed
            mock_collection.insert_many.assert_called_once()
            assert len(audit_service._pending_logs) == 0
    
    @pytest.mark.asyncio
    async def test_batch_flush_error_handling(self, audit_service):
        """Test error handling during batch flush"""
        
        with patch('services.audit.get_audit_logs_collection') as mock_get_collection:
            mock_collection = AsyncMock()
            mock_get_collection.return_value = mock_collection
            mock_collection.insert_many.side_effect = Exception("Database error")
            
            # Add logs to trigger flush
            for i in range(5):
                await audit_service.log_audit_event(
                    action=AuditAction.USER_LOGOUT,
                    user_id=f"user_{i}",
                    details={"reason": "timeout"}
                )
            
            # Should have attempted to flush and handled error
            mock_collection.insert_many.assert_called_once()
            assert audit_service._metrics["logs_failed"] == 5
            
            # Logs should be cleared even on error to prevent memory buildup
            assert len(audit_service._pending_logs) == 0


class TestPeriodicFlush:
    """Test periodic flush functionality"""
    
    @pytest.fixture
    def audit_service(self):
        service = AuditService()
        service._flush_interval = 0.1  # 100ms for testing
        return service
    
    @pytest.mark.asyncio
    async def test_periodic_flush_task(self, audit_service):
        """Test periodic flush background task"""
        
        with patch('services.audit.get_audit_logs_collection') as mock_get_collection:
            mock_collection = AsyncMock()
            mock_get_collection.return_value = mock_collection
            mock_collection.insert_many.return_value = MagicMock(inserted_ids=["id1"])
            
            # Start the flush task
            audit_service.start_flush_task()
            
            # Add a log
            await audit_service.log_audit_event(
                action=AuditAction.SECURITY_ALERT,
                user_id="admin",
                details={"alert_type": "suspicious_activity"}
            )
            
            # Wait for periodic flush
            await asyncio.sleep(0.2)
            
            # Should have been flushed by background task
            mock_collection.insert_many.assert_called_once()
            
            # Stop the task
            audit_service.stop_flush_task()
    
    @pytest.mark.asyncio
    async def test_flush_task_lifecycle(self, audit_service):
        """Test flush task start/stop lifecycle"""
        
        # Initially no task
        assert audit_service._flush_task is None
        
        # Start task
        audit_service.start_flush_task()
        assert audit_service._flush_task is not None
        assert not audit_service._flush_task.done()
        
        # Stop task
        audit_service.stop_flush_task()
        await asyncio.sleep(0.1)  # Allow task to complete
        
        assert audit_service._flush_task is None or audit_service._flush_task.done()


class TestAuditQueries:
    """Test audit log querying functionality"""
    
    @pytest.fixture
    def audit_service(self):
        return AuditService()
    
    @pytest.mark.asyncio
    async def test_get_user_audit_logs(self, audit_service):
        """Test retrieving audit logs for a specific user"""
        
        user_id = "user_123"
        
        with patch('services.audit.get_audit_logs_collection') as mock_get_collection:
            mock_collection = AsyncMock()
            mock_get_collection.return_value = mock_collection
            
            # Mock audit logs
            mock_logs = [
                {
                    "_id": "log1",
                    "action": AuditAction.USER_LOGIN.value,
                    "user_id": user_id,
                    "timestamp": datetime.now(timezone.utc),
                    "details": {"ip_address": "192.168.1.100"}
                },
                {
                    "_id": "log2", 
                    "action": AuditAction.DOCUMENT_CREATED.value,
                    "user_id": user_id,
                    "timestamp": datetime.now(timezone.utc),
                    "details": {"filename": "test.pdf"}
                }
            ]
            mock_collection.find.return_value.sort.return_value.limit.return_value.to_list.return_value = mock_logs
            
            logs = await audit_service.get_user_audit_logs(
                user_id=user_id,
                limit=100
            )
            
            assert len(logs) == 2
            assert all(log["user_id"] == user_id for log in logs)
            
            # Verify query parameters
            mock_collection.find.assert_called_once()
            query = mock_collection.find.call_args[0][0]
            assert query["user_id"] == user_id
    
    @pytest.mark.asyncio
    async def test_get_audit_logs_by_action(self, audit_service):
        """Test retrieving audit logs by action type"""
        
        action = AuditAction.DOCUMENT_UPLOADED
        
        with patch('services.audit.get_audit_logs_collection') as mock_get_collection:
            mock_collection = AsyncMock()
            mock_get_collection.return_value = mock_collection
            
            mock_logs = [
                {
                    "_id": "log1",
                    "action": action.value,
                    "user_id": "user1",
                    "timestamp": datetime.now(timezone.utc)
                },
                {
                    "_id": "log2",
                    "action": action.value,
                    "user_id": "user2", 
                    "timestamp": datetime.now(timezone.utc)
                }
            ]
            mock_collection.find.return_value.sort.return_value.limit.return_value.to_list.return_value = mock_logs
            
            logs = await audit_service.get_audit_logs_by_action(
                action=action,
                limit=50
            )
            
            assert len(logs) == 2
            assert all(log["action"] == action.value for log in logs)
    
    @pytest.mark.asyncio
    async def test_get_audit_logs_by_timerange(self, audit_service):
        """Test retrieving audit logs within time range"""
        
        start_time = datetime.now(timezone.utc) - timedelta(hours=24)
        end_time = datetime.now(timezone.utc)
        
        with patch('services.audit.get_audit_logs_collection') as mock_get_collection:
            mock_collection = AsyncMock()
            mock_get_collection.return_value = mock_collection
            
            mock_logs = [
                {
                    "_id": "log1",
                    "action": AuditAction.USER_LOGIN.value,
                    "timestamp": start_time + timedelta(hours=1)
                },
                {
                    "_id": "log2",
                    "action": AuditAction.USER_LOGOUT.value,
                    "timestamp": start_time + timedelta(hours=2)
                }
            ]
            mock_collection.find.return_value.sort.return_value.limit.return_value.to_list.return_value = mock_logs
            
            logs = await audit_service.get_audit_logs_by_timerange(
                start_time=start_time,
                end_time=end_time,
                limit=100
            )
            
            assert len(logs) == 2
            
            # Verify time range query
            query = mock_collection.find.call_args[0][0]
            assert "timestamp" in query
            assert "$gte" in query["timestamp"]
            assert "$lte" in query["timestamp"]
    
    @pytest.mark.asyncio
    async def test_search_audit_logs(self, audit_service):
        """Test searching audit logs with filters"""
        
        filters = {
            "user_id": "user_123",
            "action": AuditAction.DOCUMENT_ACCESSED.value,
            "resource_type": "document"
        }
        
        with patch('services.audit.get_audit_logs_collection') as mock_get_collection:
            mock_collection = AsyncMock()
            mock_get_collection.return_value = mock_collection
            
            mock_logs = [
                {
                    "_id": "log1",
                    "action": AuditAction.DOCUMENT_ACCESSED.value,
                    "user_id": "user_123",
                    "resource_type": "document",
                    "resource_id": "doc_456"
                }
            ]
            mock_collection.find.return_value.sort.return_value.limit.return_value.to_list.return_value = mock_logs
            
            logs = await audit_service.search_audit_logs(
                filters=filters,
                limit=50
            )
            
            assert len(logs) == 1
            assert logs[0]["user_id"] == "user_123"
            assert logs[0]["action"] == AuditAction.DOCUMENT_ACCESSED.value


class TestComplianceReporting:
    """Test compliance and reporting functionality"""
    
    @pytest.fixture
    def audit_service(self):
        return AuditService()
    
    @pytest.mark.asyncio
    async def test_generate_compliance_report(self, audit_service):
        """Test compliance report generation"""
        
        start_date = datetime.now(timezone.utc) - timedelta(days=30)
        end_date = datetime.now(timezone.utc)
        
        with patch('services.audit.get_audit_logs_collection') as mock_get_collection:
            mock_collection = AsyncMock()
            mock_get_collection.return_value = mock_collection
            
            # Mock aggregation pipeline results
            mock_collection.aggregate.return_value.to_list.return_value = [
                {"_id": AuditAction.USER_LOGIN.value, "count": 150},
                {"_id": AuditAction.DOCUMENT_CREATED.value, "count": 75},
                {"_id": AuditAction.DOCUMENT_ACCESSED.value, "count": 300},
                {"_id": AuditAction.SECURITY_ALERT.value, "count": 5}
            ]
            
            report = await audit_service.generate_compliance_report(
                start_date=start_date,
                end_date=end_date
            )
            
            assert report is not None
            assert "period" in report
            assert "total_events" in report
            assert "events_by_action" in report
            assert "security_events" in report
            
            assert report["total_events"] == 530  # Sum of all counts
            assert report["events_by_action"][AuditAction.USER_LOGIN.value] == 150
            assert report["security_events"] == 5
    
    @pytest.mark.asyncio
    async def test_generate_user_activity_report(self, audit_service):
        """Test user activity report generation"""
        
        user_id = "user_123"
        
        with patch('services.audit.get_audit_logs_collection') as mock_get_collection:
            mock_collection = AsyncMock()
            mock_get_collection.return_value = mock_collection
            
            # Mock user activity data
            mock_collection.find.return_value.sort.return_value.to_list.return_value = [
                {
                    "action": AuditAction.USER_LOGIN.value,
                    "timestamp": datetime.now(timezone.utc) - timedelta(hours=1),
                    "details": {"ip_address": "192.168.1.100"}
                },
                {
                    "action": AuditAction.DOCUMENT_CREATED.value,
                    "timestamp": datetime.now(timezone.utc) - timedelta(minutes=30),
                    "details": {"filename": "report.pdf"}
                }
            ]
            
            report = await audit_service.generate_user_activity_report(
                user_id=user_id,
                days=7
            )
            
            assert report is not None
            assert report["user_id"] == user_id
            assert "activity_summary" in report
            assert "recent_activities" in report
            assert len(report["recent_activities"]) == 2


class TestSecurityAuditing:
    """Test security-specific auditing functionality"""
    
    @pytest.fixture
    def audit_service(self):
        return AuditService()
    
    @pytest.mark.asyncio
    async def test_log_security_event(self, audit_service):
        """Test logging of security events"""
        
        with patch('services.audit.get_audit_logs_collection') as mock_get_collection:
            mock_collection = AsyncMock()
            mock_get_collection.return_value = mock_collection
            mock_collection.insert_many.return_value = MagicMock(inserted_ids=["sec_id1"])
            
            await audit_service.log_security_event(
                event_type="failed_login_attempt",
                severity="high",
                user_id="user_123",
                ip_address="192.168.1.100",
                details={
                    "attempts": 5,
                    "user_agent": "Chrome/91.0",
                    "reason": "invalid_password"
                }
            )
            
            # Should have added security-specific fields
            assert len(audit_service._pending_logs) == 1
            log_entry = audit_service._pending_logs[0]
            
            assert log_entry["action"] == AuditAction.SECURITY_ALERT.value
            assert log_entry["details"]["event_type"] == "failed_login_attempt"
            assert log_entry["details"]["severity"] == "high"
            assert log_entry["details"]["ip_address"] == "192.168.1.100"
    
    @pytest.mark.asyncio
    async def test_detect_suspicious_activity(self, audit_service):
        """Test suspicious activity detection"""
        
        user_id = "user_suspicious"
        
        with patch('services.audit.get_audit_logs_collection') as mock_get_collection:
            mock_collection = AsyncMock()
            mock_get_collection.return_value = mock_collection
            
            # Mock recent failed login attempts
            mock_collection.find.return_value.to_list.return_value = [
                {
                    "action": AuditAction.SECURITY_ALERT.value,
                    "user_id": user_id,
                    "timestamp": datetime.now(timezone.utc) - timedelta(minutes=1),
                    "details": {"event_type": "failed_login_attempt"}
                },
                {
                    "action": AuditAction.SECURITY_ALERT.value,
                    "user_id": user_id,
                    "timestamp": datetime.now(timezone.utc) - timedelta(minutes=2),
                    "details": {"event_type": "failed_login_attempt"}
                },
                {
                    "action": AuditAction.SECURITY_ALERT.value,
                    "user_id": user_id,
                    "timestamp": datetime.now(timezone.utc) - timedelta(minutes=3),
                    "details": {"event_type": "failed_login_attempt"}
                }
            ]
            
            is_suspicious = await audit_service.detect_suspicious_activity(
                user_id=user_id,
                timeframe_minutes=5
            )
            
            assert is_suspicious is True
            
            # Verify query for recent security events
            mock_collection.find.assert_called_once()
            query = mock_collection.find.call_args[0][0]
            assert query["user_id"] == user_id
            assert query["action"] == AuditAction.SECURITY_ALERT.value


class TestRateLimiting:
    """Test rate limiting for audit operations"""
    
    @pytest.fixture
    def audit_service(self):
        return AuditService()
    
    @pytest.mark.asyncio
    async def test_audit_rate_limiting(self, audit_service):
        """Test rate limiting for audit log creation"""
        
        with patch.object(audit_service._rate_limiter, 'check_rate_limit') as mock_rate_limit:
            mock_rate_limit.return_value = {
                "allowed": False,
                "remaining": 0,
                "reset_time": int(time.time()) + 3600,
                "error": "Audit rate limit exceeded"
            }
            
            result = await audit_service.log_audit_event(
                action=AuditAction.USER_LOGIN,
                user_id="rate_limited_user",
                details={"test": "rate_limiting"}
            )
            
            assert result is False
            
            # Log should not be added to pending logs
            assert len(audit_service._pending_logs) == 0
            
            # Rate limit should have been checked
            mock_rate_limit.assert_called_once()


class TestHealthCheck:
    """Test health check functionality"""
    
    @pytest.fixture
    def audit_service(self):
        return AuditService()
    
    @pytest.mark.asyncio
    async def test_health_check_healthy(self, audit_service):
        """Test health check when service is healthy"""
        
        with patch('services.audit.get_audit_logs_collection') as mock_get_collection:
            mock_collection = AsyncMock()
            mock_get_collection.return_value = mock_collection
            mock_collection.find_one.return_value = {"test": "connection"}
            
            health = await audit_service.health_check()
            
            assert health["status"] == "healthy"
            assert "database_connection" in health
            assert health["database_connection"] is True
            assert "pending_logs_count" in health
            assert "response_time" in health
    
    @pytest.mark.asyncio
    async def test_health_check_unhealthy(self, audit_service):
        """Test health check when service is unhealthy"""
        
        with patch('services.audit.get_audit_logs_collection') as mock_get_collection:
            mock_get_collection.side_effect = Exception("Database connection failed")
            
            health = await audit_service.health_check()
            
            assert health["status"] == "unhealthy"
            assert "error" in health
            assert "database connection failed" in health["error"].lower()


class TestMetrics:
    """Test metrics collection and reporting"""
    
    @pytest.fixture
    def audit_service(self):
        return AuditService()
    
    def test_metrics_initialization(self, audit_service):
        """Test metrics are properly initialized"""
        
        expected_metrics = [
            "logs_recorded", "logs_failed", "batch_flushes",
            "total_processing_time", "security_events", "rate_limit_hits"
        ]
        
        for metric in expected_metrics:
            assert metric in audit_service._metrics
            assert isinstance(audit_service._metrics[metric], (int, float))
    
    @pytest.mark.asyncio
    async def test_metrics_update_on_operations(self, audit_service):
        """Test metrics are updated during operations"""
        
        initial_recorded = audit_service._metrics["logs_recorded"]
        
        with patch('services.audit.get_audit_logs_collection') as mock_get_collection:
            mock_collection = AsyncMock()
            mock_get_collection.return_value = mock_collection
            mock_collection.insert_many.return_value = MagicMock(inserted_ids=["id1"])
            
            # Set small batch size for immediate flush
            audit_service._batch_size = 1
            
            await audit_service.log_audit_event(
                action=AuditAction.DOCUMENT_DELETED,
                user_id="metrics_user",
                details={"test": "metrics"}
            )
            
            assert audit_service._metrics["logs_recorded"] == initial_recorded + 1
    
    def test_get_metrics(self, audit_service):
        """Test metrics retrieval"""
        
        # Set test metrics
        audit_service._metrics.update({
            "logs_recorded": 1000,
            "logs_failed": 5,
            "batch_flushes": 100,
            "security_events": 25,
            "total_processing_time": 50.0
        })
        
        metrics = audit_service.get_metrics()
        
        assert metrics["logs_recorded"] == 1000
        assert metrics["logs_failed"] == 5
        assert metrics["batch_flushes"] == 100
        assert metrics["security_events"] == 25
        assert "success_rate" in metrics
        assert "average_processing_time" in metrics
        
        # Verify calculated metrics
        expected_success_rate = (1000 / (1000 + 5)) * 100
        assert abs(metrics["success_rate"] - expected_success_rate) < 0.01


class TestCleanup:
    """Test cleanup and resource management"""
    
    @pytest.fixture
    def audit_service(self):
        return AuditService()
    
    @pytest.mark.asyncio
    async def test_service_cleanup(self, audit_service):
        """Test service cleanup"""
        
        # Start flush task
        audit_service.start_flush_task()
        assert audit_service._flush_task is not None
        
        # Add some pending logs
        await audit_service.log_audit_event(
            action=AuditAction.USER_LOGOUT,
            user_id="cleanup_user",
            details={"reason": "session_timeout"}
        )
        
        assert len(audit_service._pending_logs) > 0
        
        with patch('services.audit.get_audit_logs_collection') as mock_get_collection:
            mock_collection = AsyncMock()
            mock_get_collection.return_value = mock_collection
            mock_collection.insert_many.return_value = MagicMock(inserted_ids=["cleanup_id"])
            
            # Cleanup should flush pending logs and stop task
            await audit_service.cleanup()
            
            # Pending logs should be flushed
            mock_collection.insert_many.assert_called_once()
            assert len(audit_service._pending_logs) == 0
            
            # Flush task should be stopped
            assert audit_service._flush_task is None or audit_service._flush_task.done()


if __name__ == "__main__":
    # Run tests with pytest
    pytest.main([__file__, "-v", "--tb=short"])