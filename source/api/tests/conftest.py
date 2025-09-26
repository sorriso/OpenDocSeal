"""
Path: infrastructure/source/api/tests/conftest.py
Version: 1
"""

import pytest
import tempfile
import os
import logging
import asyncio
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch
from typing import Dict, Any, Generator

import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# Configure pytest
def pytest_configure(config):
    """Configure pytest with custom markers and settings"""
    # Register custom markers
    config.addinivalue_line("markers", "unit: mark test as unit test")
    config.addinivalue_line("markers", "integration: mark test as integration test")
    config.addinivalue_line("markers", "slow: mark test as slow running")
    config.addinivalue_line("markers", "security: mark test as security-related")
    config.addinivalue_line("markers", "performance: mark test as performance test")


# Async test support
@pytest.fixture(scope="session")
def event_loop():
    """Create an instance of the default event loop for the test session"""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


# Logging fixtures
@pytest.fixture
def temp_log_file():
    """Create temporary log file for testing"""
    with tempfile.NamedTemporaryFile(mode='w+', suffix='.log', delete=False) as f:
        temp_file = f.name
    
    yield temp_file
    
    # Cleanup
    try:
        os.unlink(temp_file)
    except FileNotFoundError:
        pass


@pytest.fixture
def temp_log_directory():
    """Create temporary directory for log files"""
    with tempfile.TemporaryDirectory() as temp_dir:
        yield temp_dir


@pytest.fixture
def mock_logger():
    """Create mock logger for testing"""
    logger = MagicMock(spec=logging.Logger)
    logger.name = "test_logger"
    logger.level = logging.INFO
    logger.handlers = []
    return logger


@pytest.fixture
def captured_logs():
    """Capture log output for testing"""
    import io
    log_capture = io.StringIO()
    handler = logging.StreamHandler(log_capture)
    
    # Create test logger
    logger = logging.getLogger("test_captured")
    logger.addHandler(handler)
    logger.setLevel(logging.DEBUG)
    
    yield logger, log_capture
    
    # Cleanup
    logger.removeHandler(handler)
    handler.close()


# Security testing fixtures
@pytest.fixture
def sample_passwords():
    """Sample passwords for security testing"""
    return {
        "weak": [
            "123456",
            "password",
            "qwerty",
            "abc123",
            "admin",
            "short"
        ],
        "strong": [
            "MyStr0ng@Password123!",
            "C0mpl3x!P@ssw0rd2024",
            "SecureP@ssw0rd789#",
            "Ungu3ss@bl3!Str1ng",
            "9!Fj#mP$7kL@2nQ8"
        ]
    }


@pytest.fixture
def sample_tokens():
    """Sample tokens for security testing"""
    return {
        "jwt_secret": "test_jwt_secret_key_minimum_32_characters_long_for_security_testing",
        "api_key": "odseal_test_api_key_123456789abcdef",
        "bearer_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test.signature"
    }


@pytest.fixture
def malicious_inputs():
    """Sample malicious inputs for security testing"""
    return {
        "xss": [
            "<script>alert('xss')</script>",
            "javascript:alert(1)",
            "<img src='x' onerror='alert(1)'>",
            "<iframe src='javascript:alert(1)'></iframe>",
            "vbscript:alert(1)"
        ],
        "sql_injection": [
            "' OR '1'='1",
            "1'; DROP TABLE users; --",
            "admin'--",
            "' UNION SELECT * FROM users--",
            "1' OR 1=1#"
        ],
        "path_traversal": [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\config\\sam",
            "....//....//....//etc//passwd",
            "..%2F..%2F..%2Fetc%2Fpasswd"
        ]
    }


@pytest.fixture
def sample_file_content():
    """Sample file content for testing"""
    return {
        "text": b"This is sample text content for testing file operations",
        "binary": bytes(range(256)),  # All possible byte values
        "empty": b"",
        "large": b"A" * 10000  # 10KB of As
    }


# Rate limiting fixtures
@pytest.fixture
def mock_request():
    """Mock FastAPI Request object"""
    class MockClient:
        def __init__(self, host="127.0.0.1"):
            self.host = host
    
    class MockRequest:
        def __init__(self, ip="127.0.0.1", headers=None):
            self.client = MockClient(ip)
            self.headers = headers or {}
            
    return MockRequest


@pytest.fixture
def rate_limit_test_data():
    """Test data for rate limiting tests"""
    return {
        "user_ids": ["user_1", "user_2", "user_3"],
        "api_keys": ["odseal_key1", "odseal_key2", "odseal_key3"],
        "ip_addresses": ["192.168.1.100", "192.168.1.101", "10.0.0.1"],
        "endpoints": ["/api/v1/documents", "/api/v1/auth/login", "/api/v1/verify"]
    }


# Time and datetime fixtures
@pytest.fixture
def fixed_time():
    """Fixed datetime for consistent testing"""
    return datetime(2024, 1, 15, 12, 0, 0, tzinfo=timezone.utc)


@pytest.fixture
def time_travel():
    """Time travel fixture for testing time-dependent functionality"""
    class TimeTraveler:
        def __init__(self):
            self.original_time = None
            
        def travel_to(self, target_time):
            """Travel to a specific time"""
            with patch('time.time', return_value=target_time.timestamp()):
                with patch('datetime.datetime.now', return_value=target_time):
                    yield target_time
                    
        def advance_by(self, seconds):
            """Advance time by specified seconds"""
            import time
            current_time = time.time()
            new_time = current_time + seconds
            
            with patch('time.time', return_value=new_time):
                yield new_time
    
    return TimeTraveler()


# Database and configuration fixtures
@pytest.fixture
def mock_settings():
    """Mock settings for testing"""
    class MockSettings:
        def __init__(self):
            self.debug = True
            self.test_mode = True
            self.log_level = "DEBUG"
            self.log_format = "text"
            self.log_correlation = True
            self.secret_key = "test_secret_key_minimum_32_characters_long"
            self.rate_limit_enabled = True
            self.rate_limit_requests = 100
            self.rate_limit_window = 3600
            
    return MockSettings()


@pytest.fixture
def sample_correlation_ids():
    """Sample correlation IDs for testing"""
    return [
        "test-correlation-123",
        "req-456789-abc",
        "trace-xyz-789",
        "corr-id-test-001"
    ]


# Error and exception fixtures
@pytest.fixture
def sample_exceptions():
    """Sample exceptions for testing error handling"""
    return {
        "value_error": ValueError("Test value error"),
        "type_error": TypeError("Test type error"),
        "key_error": KeyError("missing_key"),
        "attribute_error": AttributeError("'NoneType' object has no attribute 'test'"),
        "runtime_error": RuntimeError("Test runtime error"),
        "custom_error": Exception("Custom test exception")
    }


# Performance testing fixtures
@pytest.fixture
def performance_timer():
    """Performance timer for testing"""
    import time
    
    class PerformanceTimer:
        def __init__(self):
            self.start_time = None
            self.end_time = None
            
        def start(self):
            self.start_time = time.perf_counter()
            
        def stop(self):
            self.end_time = time.perf_counter()
            return self.elapsed
            
        @property
        def elapsed(self):
            if self.start_time and self.end_time:
                return self.end_time - self.start_time
            return None
            
        def __enter__(self):
            self.start()
            return self
            
        def __exit__(self, exc_type, exc_val, exc_tb):
            self.stop()
    
    return PerformanceTimer


# Cleanup fixtures
@pytest.fixture(autouse=True)
def cleanup_test_environment():
    """Automatic cleanup after each test"""
    # Pre-test setup
    yield
    
    # Post-test cleanup
    # Clear any global state, caches, etc.
    import gc
    gc.collect()


@pytest.fixture(scope="function")
def isolated_test():
    """Ensure test isolation by clearing caches and global state"""
    # Clear any module-level caches
    import sys
    
    # Store original state
    original_modules = sys.modules.copy()
    
    yield
    
    # Restore original state if needed
    # This can help prevent test pollution
    pass


# Marker-based fixtures
@pytest.fixture
def skip_slow_tests(request):
    """Skip slow tests unless specifically requested"""
    if request.config.getoption("--runslow") is False:
        if "slow" in request.keywords:
            pytest.skip("need --runslow option to run")


def pytest_addoption(parser):
    """Add custom command line options"""
    parser.addoption(
        "--runslow", 
        action="store_true", 
        default=False, 
        help="run slow tests"
    )
    parser.addoption(
        "--runintegration",
        action="store_true",
        default=False,
        help="run integration tests"
    )


def pytest_collection_modifyitems(config, items):
    """Modify test collection based on markers"""
    if config.getoption("--runslow"):
        # Don't skip slow tests
        return
        
    skip_slow = pytest.mark.skip(reason="need --runslow option to run")
    for item in items:
        if "slow" in item.keywords:
            item.add_marker(skip_slow)
            
    if not config.getoption("--runintegration"):
        skip_integration = pytest.mark.skip(reason="need --runintegration option to run")
        for item in items:
            if "integration" in item.keywords:
                item.add_marker(skip_integration)


# Session-level fixtures for resource management
@pytest.fixture(scope="session")
def test_session_data():
    """Session-level data that persists across all tests"""
    return {
        "session_id": "test_session_" + str(int(datetime.now().timestamp())),
        "start_time": datetime.now(timezone.utc),
        "test_count": 0
    }


@pytest.fixture(scope="module") 
def module_setup():
    """Module-level setup and teardown"""
    # Module setup
    print("Setting up module")
    
    yield
    
    # Module teardown
    print("Tearing down module")


# Debugging fixtures
@pytest.fixture
def debug_mode():
    """Enable debug mode for tests"""
    original_debug = os.environ.get("DEBUG", "false")
    os.environ["DEBUG"] = "true"
    
    yield True
    
    os.environ["DEBUG"] = original_debug


@pytest.fixture
def capture_stdout():
    """Capture stdout for testing print statements"""
    import sys
    from io import StringIO
    
    old_stdout = sys.stdout
    sys.stdout = captured_output = StringIO()
    
    yield captured_output
    
    sys.stdout = old_stdout


if __name__ == "__main__":
    print("This file contains pytest fixtures and should be run with pytest")