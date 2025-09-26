"""
Path: infrastructure/source/api/tests/test_logging.py
Version: 1
"""

import pytest
import logging
import json
import tempfile
import os
import time
from unittest.mock import patch, MagicMock, mock_open
from datetime import datetime
from contextlib import contextmanager
from io import StringIO

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.logging import (
    setup_logging, get_logger, JSONFormatter, TextFormatter,
    CorrelatedLogger, CorrelatedTimedLogger, LoggerMixin,
    set_correlation_context, clear_correlation_context, get_correlation_context,
    correlation_context, timed_operation, log_exception,
    log_audit_event, log_performance, log_security_event
)


class TestLoggingSetup:
    """Test logging setup and configuration"""
    
    def test_setup_logging_basic(self):
        """Test basic logging setup"""
        with tempfile.TemporaryDirectory() as temp_dir:
            log_file = os.path.join(temp_dir, "test.log")
            
            # Setup logging with file
            setup_logging("INFO", log_file)
            
            # Verify logger configuration
            logger = logging.getLogger("test")
            assert logger.level <= logging.INFO
            
            # Test log message
            logger.info("Test message")
            
            # Verify file was created
            assert os.path.exists(log_file)
            
    def test_setup_logging_json_format(self):
        """Test logging setup with JSON format"""
        with tempfile.TemporaryDirectory() as temp_dir:
            log_file = os.path.join(temp_dir, "test_json.log")
            
            setup_logging("DEBUG", log_file, json_format=True)
            
            logger = logging.getLogger("test_json")
            logger.info("JSON test message", extra={"test_field": "test_value"})
            
            # Verify JSON format in file
            with open(log_file, 'r') as f:
                content = f.read()
                # Should contain JSON structure
                assert '"message"' in content
                assert '"test_field"' in content
                
    def test_setup_logging_rotation(self):
        """Test logging setup with file rotation"""
        with tempfile.TemporaryDirectory() as temp_dir:
            log_file = os.path.join(temp_dir, "test_rotation.log")
            
            # Setup with small max size for testing
            setup_logging(
                "INFO", 
                log_file,
                max_file_size=1024,  # 1KB
                backup_count=3
            )
            
            logger = logging.getLogger("test_rotation")
            
            # Generate enough log messages to trigger rotation
            for i in range(200):
                logger.info(f"Log message number {i} with some additional content to make it longer")
            
            # Should have created backup files
            log_files = [f for f in os.listdir(temp_dir) if f.startswith("test_rotation.log")]
            assert len(log_files) > 1  # Original + backups
            
    def test_get_logger(self):
        """Test logger retrieval"""
        logger_name = "test_get_logger"
        logger = get_logger(logger_name)
        
        assert logger is not None
        assert logger.name == logger_name
        assert isinstance(logger, logging.Logger)
        
        # Should return same instance
        logger2 = get_logger(logger_name)
        assert logger is logger2


class TestLogFormatters:
    """Test custom log formatters"""
    
    def test_json_formatter(self):
        """Test JSON log formatter"""
        formatter = JSONFormatter()
        
        # Create test record
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="/test/path.py",
            lineno=42,
            msg="Test message %s",
            args=("arg1",),
            exc_info=None
        )
        record.correlation_id = "test-correlation-123"
        record.user_id = "user-456"
        
        formatted = formatter.format(record)
        
        # Should be valid JSON
        data = json.loads(formatted)
        
        assert data["message"] == "Test message arg1"
        assert data["level"] == "INFO"
        assert data["logger"] == "test"
        assert data["correlation_id"] == "test-correlation-123"
        assert data["user_id"] == "user-456"
        assert "timestamp" in data
        
    def test_text_formatter(self):
        """Test text log formatter"""
        formatter = TextFormatter()
        
        # Create test record
        record = logging.LogRecord(
            name="test",
            level=logging.WARNING,
            pathname="/test/path.py",
            lineno=42,
            msg="Test warning message",
            args=(),
            exc_info=None
        )
        record.correlation_id = "test-correlation-789"
        
        formatted = formatter.format(record)
        
        assert "WARNING" in formatted
        assert "Test warning message" in formatted
        assert "test-correlation-789" in formatted
        assert record.created is not None


class TestCorrelationLogging:
    """Test correlation logging functionality"""
    
    def test_correlation_context_manager(self):
        """Test correlation context management"""
        correlation_id = "test-correlation-123"
        
        # Initially no correlation
        assert get_correlation_context() is None
        
        # Set correlation
        set_correlation_context(correlation_id)
        assert get_correlation_context() == correlation_id
        
        # Clear correlation
        clear_correlation_context()
        assert get_correlation_context() is None
        
    def test_correlation_context_decorator(self):
        """Test correlation context decorator"""
        correlation_id = "decorator-test-456"
        
        @correlation_context(correlation_id)
        def test_function():
            return get_correlation_context()
        
        # Before function call
        assert get_correlation_context() is None
        
        # During function call
        result = test_function()
        assert result == correlation_id
        
        # After function call
        assert get_correlation_context() is None
        
    def test_correlated_logger(self):
        """Test correlated logger functionality"""
        correlation_id = "logger-test-789"
        
        # Create logger with correlation
        logger = CorrelatedLogger("test_correlated", correlation_id)
        
        # Capture log output
        with patch('logging.Logger.info') as mock_info:
            logger.info("Test message")
            
            # Verify correlation was added
            mock_info.assert_called_once()
            args, kwargs = mock_info.call_args
            assert 'extra' in kwargs
            assert kwargs['extra']['correlation_id'] == correlation_id
            
    def test_correlated_timed_logger(self):
        """Test correlated timed logger"""
        correlation_id = "timed-test-123"
        
        logger = CorrelatedTimedLogger("test_timed", correlation_id)
        
        with patch('logging.Logger.info') as mock_info:
            with logger.timed_operation("test_operation"):
                time.sleep(0.1)  # Simulate work
            
            # Should have logged performance info
            assert mock_info.call_count >= 1
            
            # Check for performance log
            calls = mock_info.call_args_list
            perf_call = None
            for call in calls:
                args, kwargs = call
                if "Performance:" in str(args):
                    perf_call = call
                    break
            
            assert perf_call is not None
            args, kwargs = perf_call
            assert 'extra' in kwargs
            assert kwargs['extra']['correlation_id'] == correlation_id


class TestLoggerMixin:
    """Test logger mixin functionality"""
    
    def test_logger_mixin_basic(self):
        """Test basic logger mixin functionality"""
        class TestClass(LoggerMixin):
            def __init__(self):
                super().__init__()
                
            def test_method(self):
                self.logger.info("Test message from mixin")
                return "success"
        
        test_obj = TestClass()
        
        # Should have logger
        assert hasattr(test_obj, 'logger')
        assert isinstance(test_obj.logger, logging.Logger)
        assert test_obj.logger.name == "TestClass"
        
        # Test logging
        with patch.object(test_obj.logger, 'info') as mock_info:
            result = test_obj.test_method()
            
            mock_info.assert_called_once_with("Test message from mixin")
            assert result == "success"
            
    def test_logger_mixin_correlation(self):
        """Test logger mixin with correlation"""
        class TestClassWithCorrelation(LoggerMixin):
            def __init__(self, correlation_id):
                super().__init__(correlation_id=correlation_id)
                
            def test_method(self):
                self.log_info("Correlated message")
        
        correlation_id = "mixin-test-456"
        test_obj = TestClassWithCorrelation(correlation_id)
        
        with patch.object(test_obj.logger, 'info') as mock_info:
            test_obj.test_method()
            
            mock_info.assert_called_once()
            args, kwargs = mock_info.call_args
            assert 'extra' in kwargs
            assert kwargs['extra']['correlation_id'] == correlation_id


class TestTimedOperations:
    """Test timed operation functionality"""
    
    def test_timed_operation_context_manager(self):
        """Test timed operation as context manager"""
        logger = logging.getLogger("test_timed")
        
        with patch.object(logger, 'info') as mock_info:
            with timed_operation(logger, "test_operation"):
                time.sleep(0.05)  # Simulate work
            
            # Should log performance info
            mock_info.assert_called_once()
            args, kwargs = mock_info.call_args
            
            assert "Performance:" in str(args[0])
            assert "test_operation" in str(args[0])
            assert 'extra' in kwargs
            assert 'duration_seconds' in kwargs['extra']
            assert kwargs['extra']['duration_seconds'] >= 0.05
            
    def test_timed_operation_decorator(self):
        """Test timed operation as decorator"""
        logger = logging.getLogger("test_timed_decorator")
        
        @timed_operation(logger, "decorated_function")
        def test_function():
            time.sleep(0.05)
            return "completed"
        
        with patch.object(logger, 'info') as mock_info:
            result = test_function()
            
            assert result == "completed"
            
            # Should log performance info
            mock_info.assert_called_once()
            args, kwargs = mock_info.call_args
            
            assert "Performance:" in str(args[0])
            assert "decorated_function" in str(args[0])


class TestSpecializedLogging:
    """Test specialized logging functions"""
    
    def test_log_exception(self):
        """Test exception logging"""
        logger = logging.getLogger("test_exception")
        
        with patch.object(logger, 'error') as mock_error:
            try:
                raise ValueError("Test exception")
            except Exception as e:
                log_exception(logger, "Operation failed", e, correlation_id="exc-123")
            
            mock_error.assert_called_once()
            args, kwargs = mock_error.call_args
            
            assert "Operation failed" in str(args[0])
            assert "ValueError: Test exception" in str(args[0])
            assert 'extra' in kwargs
            assert kwargs['extra']['correlation_id'] == "exc-123"
            assert 'exc_info' in kwargs['extra']
            
    def test_log_audit_event(self):
        """Test audit event logging"""
        logger = logging.getLogger("test_audit")
        
        with patch.object(logger, 'info') as mock_info:
            log_audit_event(
                logger,
                action="document_create",
                user_id="user-123",
                details={"document_id": "doc-456", "name": "test.pdf"},
                correlation_id="audit-789"
            )
            
            mock_info.assert_called_once()
            args, kwargs = mock_info.call_args
            
            assert "Audit:" in str(args[0])
            assert "document_create" in str(args[0])
            assert 'extra' in kwargs
            
            extra = kwargs['extra']
            assert extra['event_type'] == 'audit'
            assert extra['action'] == 'document_create'
            assert extra['user_id'] == 'user-123'
            assert extra['correlation_id'] == 'audit-789'
            assert 'details' in extra
            
    def test_log_performance(self):
        """Test performance logging"""
        logger = logging.getLogger("test_performance")
        
        with patch.object(logger, 'info') as mock_info:
            log_performance(
                logger,
                operation="database_query",
                duration=1.234,
                query_type="select",
                correlation_id="perf-456"
            )
            
            mock_info.assert_called_once()
            args, kwargs = mock_info.call_args
            
            assert "Performance:" in str(args[0])
            assert "database_query" in str(args[0])
            assert "1.234s" in str(args[0])
            
            extra = kwargs['extra']
            assert extra['event_type'] == 'performance'
            assert extra['operation'] == 'database_query'
            assert extra['duration_seconds'] == 1.234
            assert extra['query_type'] == 'select'
            assert extra['correlation_id'] == 'perf-456'
            
    def test_log_security_event(self):
        """Test security event logging"""
        logger = logging.getLogger("test_security")
        
        # Test different severity levels
        security_tests = [
            ("low", "info"),
            ("medium", "warning"), 
            ("high", "error"),
            ("critical", "critical")
        ]
        
        for severity, expected_level in security_tests:
            with patch.object(logger, expected_level) as mock_log:
                log_security_event(
                    logger,
                    event_type="failed_login",
                    severity=severity,
                    user_id="user-123",
                    ip_address="192.168.1.100",
                    details={"attempts": 3},
                    correlation_id=f"sec-{severity}"
                )
                
                mock_log.assert_called_once()
                args, kwargs = mock_log.call_args
                
                assert "Security:" in str(args[0])
                assert "failed_login" in str(args[0])
                
                extra = kwargs['extra']
                assert extra['event_type'] == 'security'
                assert extra['security_event'] == 'failed_login'
                assert extra['severity'] == severity
                assert extra['user_id'] == 'user-123'
                assert extra['ip_address'] == '192.168.1.100'
                assert extra['correlation_id'] == f'sec-{severity}'


class TestLoggerIntegration:
    """Test logger integration scenarios"""
    
    def test_logger_with_correlation_flow(self):
        """Test complete logging flow with correlation"""
        correlation_id = "integration-test-123"
        
        # Setup logger
        logger = get_logger("integration_test")
        
        # Simulate request processing with correlation
        set_correlation_context(correlation_id)
        
        try:
            with patch.object(logger, 'info') as mock_info, \
                 patch.object(logger, 'warning') as mock_warning:
                
                # Log various events during request
                logger.info("Request started", extra={
                    'correlation_id': get_correlation_context(),
                    'endpoint': '/api/v1/documents'
                })
                
                # Simulate some processing
                with timed_operation(logger, "document_processing"):
                    time.sleep(0.01)
                
                # Log security event
                log_security_event(
                    logger,
                    event_type="document_access",
                    severity="low",
                    user_id="user-789",
                    correlation_id=get_correlation_context()
                )
                
                # Verify all logs have correlation
                for mock in [mock_info, mock_warning]:
                    if mock.called:
                        for call in mock.call_args_list:
                            args, kwargs = call
                            if 'extra' in kwargs and 'correlation_id' in kwargs['extra']:
                                assert kwargs['extra']['correlation_id'] == correlation_id
        
        finally:
            clear_correlation_context()
            
    def test_logger_error_handling(self):
        """Test logger error handling"""
        logger = get_logger("error_test")
        
        # Test with invalid log level
        with patch('logging.getLogger') as mock_get_logger:
            mock_logger = MagicMock()
            mock_logger.info.side_effect = Exception("Logging failed")
            mock_get_logger.return_value = mock_logger
            
            # Should not raise exception
            try:
                test_logger = get_logger("failing_logger")
                test_logger.info("This should not crash")
            except Exception as e:
                pytest.fail(f"Logger should handle errors gracefully: {e}")


# Integration test fixtures
@pytest.fixture
def temp_log_file():
    """Temporary log file for testing"""
    with tempfile.NamedTemporaryFile(mode='w+', suffix='.log', delete=False) as f:
        temp_file = f.name
    
    yield temp_file
    
    # Cleanup
    try:
        os.unlink(temp_file)
    except FileNotFoundError:
        pass


@pytest.fixture
def sample_correlation_id():
    """Sample correlation ID for testing"""
    return "test-correlation-" + str(int(time.time()))


@pytest.fixture
def mock_logger():
    """Mock logger for testing"""
    logger = MagicMock(spec=logging.Logger)
    logger.name = "mock_logger"
    logger.level = logging.INFO
    return logger


if __name__ == "__main__":
    # Run tests with pytest
    pytest.main([__file__, "-v"])