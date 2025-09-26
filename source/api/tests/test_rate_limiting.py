"""
Path: infrastructure/source/api/tests/test_rate_limiting.py
Version: 1
"""

import pytest
import asyncio
import time
from datetime import datetime, timezone, timedelta
from unittest.mock import patch, MagicMock

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.rate_limiting import (
    RateLimiter, RateLimitRule, RateLimitResult, RateLimitStrategy,
    FixedWindowLimiter, SlidingWindowLimiter, TokenBucketLimiter, LeakyBucketLimiter,
    RATE_LIMIT_RULES, create_rate_limiter, get_client_identifier,
    get_user_identifier, get_api_key_identifier
)


class TestRateLimitRule:
    """Test rate limit rule creation and validation"""
    
    def test_rate_limit_rule_creation(self):
        """Test basic rate limit rule creation"""
        rule = RateLimitRule(
            requests=100,
            window=3600,
            strategy=RateLimitStrategy.FIXED_WINDOW
        )
        
        assert rule.requests == 100
        assert rule.window == 3600
        assert rule.strategy == RateLimitStrategy.FIXED_WINDOW
        assert rule.burst_multiplier == 1.0
        assert rule.enabled == True
        
    def test_rate_limit_rule_with_burst(self):
        """Test rate limit rule with burst multiplier"""
        rule = RateLimitRule(
            requests=100,
            window=3600,
            strategy=RateLimitStrategy.TOKEN_BUCKET,
            burst_multiplier=1.5
        )
        
        assert rule.burst_multiplier == 1.5
        
    def test_rate_limit_rule_validation(self):
        """Test rate limit rule validation"""
        # Test invalid values
        with pytest.raises(ValueError):
            RateLimitRule(requests=0, window=3600)
            
        with pytest.raises(ValueError):
            RateLimitRule(requests=100, window=0)
            
        with pytest.raises(ValueError):
            RateLimitRule(requests=100, window=3600, burst_multiplier=0.5)


class TestRateLimitResult:
    """Test rate limit result model"""
    
    def test_rate_limit_result_allowed(self):
        """Test allowed rate limit result"""
        reset_time = datetime.now(timezone.utc) + timedelta(seconds=3600)
        
        result = RateLimitResult(
            allowed=True,
            requests_remaining=50,
            reset_time=reset_time
        )
        
        assert result.allowed == True
        assert result.requests_remaining == 50
        assert result.reset_time == reset_time
        assert result.retry_after is None
        
    def test_rate_limit_result_denied(self):
        """Test denied rate limit result"""
        reset_time = datetime.now(timezone.utc) + timedelta(seconds=300)
        
        result = RateLimitResult(
            allowed=False,
            requests_remaining=0,
            reset_time=reset_time,
            retry_after=300
        )
        
        assert result.allowed == False
        assert result.requests_remaining == 0
        assert result.retry_after == 300


class TestFixedWindowLimiter:
    """Test fixed window rate limiter"""
    
    @pytest.mark.asyncio
    async def test_fixed_window_basic(self):
        """Test basic fixed window functionality"""
        rule = RateLimitRule(
            requests=5,
            window=60,  # 1 minute window
            strategy=RateLimitStrategy.FIXED_WINDOW
        )
        
        limiter = FixedWindowLimiter(rule)
        key = "test_user_1"
        
        # First 5 requests should be allowed
        for i in range(5):
            result = await limiter.is_allowed(key)
            assert result.allowed == True
            assert result.requests_remaining == 4 - i
            
        # 6th request should be denied
        result = await limiter.is_allowed(key)
        assert result.allowed == False
        assert result.requests_remaining == 0
        assert result.retry_after is not None
        
    @pytest.mark.asyncio
    async def test_fixed_window_reset(self):
        """Test fixed window reset after time window"""
        rule = RateLimitRule(
            requests=2,
            window=1,  # 1 second window
            strategy=RateLimitStrategy.FIXED_WINDOW
        )
        
        limiter = FixedWindowLimiter(rule)
        key = "test_user_2"
        
        # Use up the limit
        result1 = await limiter.is_allowed(key)
        result2 = await limiter.is_allowed(key)
        assert result1.allowed == True
        assert result2.allowed == True
        
        # Should be rate limited
        result3 = await limiter.is_allowed(key)
        assert result3.allowed == False
        
        # Wait for window to reset
        await asyncio.sleep(1.1)
        
        # Should be allowed again
        result4 = await limiter.is_allowed(key)
        assert result4.allowed == True
        
    @pytest.mark.asyncio
    async def test_fixed_window_multiple_keys(self):
        """Test fixed window with multiple keys"""
        rule = RateLimitRule(requests=2, window=60)
        limiter = FixedWindowLimiter(rule)
        
        # Different users should have separate limits
        result1 = await limiter.is_allowed("user1")
        result2 = await limiter.is_allowed("user2")
        result3 = await limiter.is_allowed("user1")
        result4 = await limiter.is_allowed("user2")
        
        assert all([result1.allowed, result2.allowed, result3.allowed, result4.allowed])
        
        # Both users should be rate limited after using their quota
        result5 = await limiter.is_allowed("user1")
        result6 = await limiter.is_allowed("user2")
        
        assert result5.allowed == False
        assert result6.allowed == False


class TestSlidingWindowLimiter:
    """Test sliding window rate limiter"""
    
    @pytest.mark.asyncio
    async def test_sliding_window_basic(self):
        """Test basic sliding window functionality"""
        rule = RateLimitRule(
            requests=3,
            window=2,  # 2 second window
            strategy=RateLimitStrategy.SLIDING_WINDOW
        )
        
        limiter = SlidingWindowLimiter(rule)
        key = "sliding_test_1"
        
        # First 3 requests should be allowed
        for i in range(3):
            result = await limiter.is_allowed(key)
            assert result.allowed == True
            
        # 4th request should be denied
        result = await limiter.is_allowed(key)
        assert result.allowed == False
        
    @pytest.mark.asyncio
    async def test_sliding_window_gradual_recovery(self):
        """Test sliding window gradual recovery"""
        rule = RateLimitRule(
            requests=2,
            window=1,  # 1 second window
            strategy=RateLimitStrategy.SLIDING_WINDOW
        )
        
        limiter = SlidingWindowLimiter(rule)
        key = "sliding_test_2"
        
        # Use up limit
        await limiter.is_allowed(key)
        await limiter.is_allowed(key)
        
        # Should be rate limited
        result = await limiter.is_allowed(key)
        assert result.allowed == False
        
        # Wait half the window
        await asyncio.sleep(0.6)
        
        # Should still be limited (requests haven't expired yet)
        result = await limiter.is_allowed(key)
        assert result.allowed == False
        
        # Wait for full window to pass
        await asyncio.sleep(0.6)  # Total 1.2 seconds
        
        # Should be allowed again
        result = await limiter.is_allowed(key)
        assert result.allowed == True


class TestTokenBucketLimiter:
    """Test token bucket rate limiter"""
    
    @pytest.mark.asyncio
    async def test_token_bucket_basic(self):
        """Test basic token bucket functionality"""
        rule = RateLimitRule(
            requests=5,
            window=10,  # 5 requests per 10 seconds = 0.5 tokens/second
            strategy=RateLimitStrategy.TOKEN_BUCKET
        )
        
        limiter = TokenBucketLimiter(rule)
        key = "bucket_test_1"
        
        # Should start with full bucket
        for i in range(5):
            result = await limiter.is_allowed(key)
            assert result.allowed == True
            
        # Should be rate limited when bucket is empty
        result = await limiter.is_allowed(key)
        assert result.allowed == False
        
    @pytest.mark.asyncio
    async def test_token_bucket_refill(self):
        """Test token bucket refill over time"""
        rule = RateLimitRule(
            requests=2,
            window=1,  # 2 requests per second
            strategy=RateLimitStrategy.TOKEN_BUCKET
        )
        
        limiter = TokenBucketLimiter(rule)
        key = "bucket_test_2"
        
        # Empty the bucket
        await limiter.is_allowed(key)
        await limiter.is_allowed(key)
        
        # Should be rate limited
        result = await limiter.is_allowed(key)
        assert result.allowed == False
        
        # Wait for token refill
        await asyncio.sleep(0.6)  # Should refill ~1 token
        
        # Should be allowed again
        result = await limiter.is_allowed(key)
        assert result.allowed == True
        
    @pytest.mark.asyncio
    async def test_token_bucket_burst(self):
        """Test token bucket burst capability"""
        rule = RateLimitRule(
            requests=2,
            window=4,  # 0.5 tokens/second
            strategy=RateLimitStrategy.TOKEN_BUCKET,
            burst_multiplier=2.0  # Allow burst of 4 tokens
        )
        
        limiter = TokenBucketLimiter(rule)
        key = "bucket_burst_test"
        
        # Should allow burst initially
        for i in range(4):  # burst_size = requests * burst_multiplier = 4
            result = await limiter.is_allowed(key)
            assert result.allowed == True
            
        # Should be rate limited after burst
        result = await limiter.is_allowed(key)
        assert result.allowed == False


class TestLeakyBucketLimiter:
    """Test leaky bucket rate limiter"""
    
    @pytest.mark.asyncio
    async def test_leaky_bucket_basic(self):
        """Test basic leaky bucket functionality"""
        rule = RateLimitRule(
            requests=3,
            window=6,  # 3 requests per 6 seconds = 0.5 requests/second
            strategy=RateLimitStrategy.LEAKY_BUCKET
        )
        
        limiter = LeakyBucketLimiter(rule)
        key = "leaky_test_1"
        
        # Should process requests at the specified rate
        result1 = await limiter.is_allowed(key)
        assert result1.allowed == True
        
        result2 = await limiter.is_allowed(key)
        assert result2.allowed == True
        
        # Rapid requests should be rate limited
        result3 = await limiter.is_allowed(key)
        result4 = await limiter.is_allowed(key)
        
        # At least one should be rate limited due to leaky bucket behavior
        denied_count = sum([1 for r in [result3, result4] if not r.allowed])
        assert denied_count > 0
        
    @pytest.mark.asyncio
    async def test_leaky_bucket_steady_rate(self):
        """Test leaky bucket steady processing rate"""
        rule = RateLimitRule(
            requests=2,
            window=1,  # 2 requests per second
            strategy=RateLimitStrategy.LEAKY_BUCKET
        )
        
        limiter = LeakyBucketLimiter(rule)
        key = "leaky_steady_test"
        
        # Send requests at steady rate
        allowed_count = 0
        for i in range(5):
            result = await limiter.is_allowed(key)
            if result.allowed:
                allowed_count += 1
            await asyncio.sleep(0.3)  # Slightly slower than allowed rate
            
        # Should allow most requests at steady rate
        assert allowed_count >= 3


class TestRateLimiterFactory:
    """Test rate limiter factory and configuration"""
    
    @pytest.mark.asyncio
    async def test_create_rate_limiter_fixed_window(self):
        """Test creating fixed window rate limiter"""
        limiter = create_rate_limiter(
            default_requests=10,
            default_window=60,
            strategy=RateLimitStrategy.FIXED_WINDOW
        )
        
        assert isinstance(limiter, RateLimiter)
        
        # Test basic functionality
        result = await limiter.is_allowed("test_key")
        assert result.allowed == True
        
    @pytest.mark.asyncio
    async def test_create_rate_limiter_with_rules(self):
        """Test creating rate limiter with predefined rules"""
        custom_rules = {
            "api_key": RateLimitRule(requests=1000, window=3600),
            "anonymous": RateLimitRule(requests=100, window=3600)
        }
        
        limiter = create_rate_limiter(
            default_requests=50,
            default_window=60,
            rules=custom_rules
        )
        
        # Test that custom rules are applied
        result = await limiter.is_allowed("api_key:user123")
        assert result.allowed == True
        
    def test_predefined_rate_limit_rules(self):
        """Test predefined rate limit rules"""
        assert "api_key" in RATE_LIMIT_RULES
        assert "anonymous" in RATE_LIMIT_RULES
        assert "auth" in RATE_LIMIT_RULES
        assert "upload" in RATE_LIMIT_RULES
        assert "admin" in RATE_LIMIT_RULES
        
        # Verify rule properties
        api_key_rule = RATE_LIMIT_RULES["api_key"]
        assert api_key_rule.requests == 1000
        assert api_key_rule.window == 3600
        
        auth_rule = RATE_LIMIT_RULES["auth"]
        assert auth_rule.requests == 5
        assert auth_rule.window == 300  # 5 minutes


class TestRateLimiterIntegration:
    """Test rate limiter integration scenarios"""
    
    @pytest.mark.asyncio
    async def test_rate_limiter_multiple_strategies(self):
        """Test rate limiter with multiple strategies"""
        rules = {
            "fixed": RateLimitRule(requests=5, window=10, strategy=RateLimitStrategy.FIXED_WINDOW),
            "sliding": RateLimitRule(requests=5, window=10, strategy=RateLimitStrategy.SLIDING_WINDOW),
            "bucket": RateLimitRule(requests=5, window=10, strategy=RateLimitStrategy.TOKEN_BUCKET)
        }
        
        limiter = RateLimiter(default_rule=rules["fixed"], rules=rules)
        
        # Test each strategy
        strategies = ["fixed", "sliding", "bucket"]
        for strategy in strategies:
            key = f"{strategy}:user123"
            
            # Should allow initial requests
            for i in range(3):
                result = await limiter.is_allowed(key)
                assert result.allowed == True, f"Strategy {strategy} failed at request {i}"
                
    @pytest.mark.asyncio
    async def test_rate_limiter_statistics(self):
        """Test rate limiter statistics collection"""
        limiter = create_rate_limiter(default_requests=10, default_window=60)
        
        # Generate some traffic
        for i in range(15):
            await limiter.is_allowed(f"stats_test_user_{i % 3}")
            
        stats = await limiter.get_statistics()
        
        assert "requests_checked" in stats
        assert "requests_allowed" in stats
        assert "requests_denied" in stats
        assert stats["requests_checked"] >= 15
        assert stats["requests_allowed"] > 0
        
    @pytest.mark.asyncio
    async def test_rate_limiter_cleanup(self):
        """Test rate limiter cleanup of old data"""
        limiter = create_rate_limiter(default_requests=5, default_window=1)  # 1 second window
        
        # Generate requests
        for i in range(3):
            await limiter.is_allowed("cleanup_test_user")
            
        # Wait for data to expire
        await asyncio.sleep(2)
        
        # Trigger cleanup (this would normally be done internally)
        if hasattr(limiter, 'cleanup'):
            await limiter.cleanup()
            
        # Verify cleanup occurred (exact verification depends on implementation)
        stats = await limiter.get_statistics()
        assert stats is not None


class TestIdentifierFunctions:
    """Test client/user identifier functions"""
    
    def test_get_client_identifier(self):
        """Test client identifier extraction"""
        # Mock request object
        class MockRequest:
            def __init__(self, remote_addr, headers):
                self.client = MockClient(remote_addr)
                self.headers = headers
                
        class MockClient:
            def __init__(self, host):
                self.host = host
        
        # Test direct IP
        request = MockRequest("192.168.1.100", {})
        identifier = get_client_identifier(request)
        assert identifier == "192.168.1.100"
        
        # Test with X-Forwarded-For
        request = MockRequest("127.0.0.1", {"x-forwarded-for": "203.0.113.1, 192.168.1.100"})
        identifier = get_client_identifier(request)
        assert identifier == "203.0.113.1"
        
        # Test with X-Real-IP
        request = MockRequest("127.0.0.1", {"x-real-ip": "203.0.113.2"})
        identifier = get_client_identifier(request)
        assert identifier == "203.0.113.2"
        
    def test_get_user_identifier(self):
        """Test user identifier extraction"""
        # Mock user object
        class MockUser:
            def __init__(self, id, email):
                self.id = id
                self.email = email
        
        user = MockUser("user123", "test@example.com")
        identifier = get_user_identifier(user)
        assert identifier == "user123"
        
        # Test with None user
        identifier = get_user_identifier(None)
        assert identifier is None
        
    def test_get_api_key_identifier(self):
        """Test API key identifier extraction"""
        api_key = "odseal_abc123def456789"
        identifier = get_api_key_identifier(api_key)
        
        # Should return a consistent hash-based identifier
        assert identifier is not None
        assert isinstance(identifier, str)
        assert len(identifier) > 10
        
        # Should be consistent for same API key
        identifier2 = get_api_key_identifier(api_key)
        assert identifier == identifier2
        
        # Should be different for different API keys
        identifier3 = get_api_key_identifier("odseal_different_key")
        assert identifier != identifier3


class TestRateLimitingEdgeCases:
    """Test rate limiting edge cases and error handling"""
    
    @pytest.mark.asyncio
    async def test_rate_limiter_with_zero_requests(self):
        """Test rate limiter behavior with zero request limit"""
        rule = RateLimitRule(requests=0, window=60)
        
        # Should raise error during rule creation
        with pytest.raises(ValueError):
            limiter = FixedWindowLimiter(rule)
            
    @pytest.mark.asyncio
    async def test_rate_limiter_with_negative_values(self):
        """Test rate limiter behavior with negative values"""
        with pytest.raises(ValueError):
            RateLimitRule(requests=-1, window=60)
            
        with pytest.raises(ValueError):
            RateLimitRule(requests=100, window=-1)
            
    @pytest.mark.asyncio
    async def test_rate_limiter_empty_key(self):
        """Test rate limiter behavior with empty key"""
        limiter = create_rate_limiter(default_requests=10, default_window=60)
        
        # Should handle empty key gracefully
        result = await limiter.is_allowed("")
        assert isinstance(result, RateLimitResult)
        
        # Should handle None key
        result = await limiter.is_allowed(None)
        assert isinstance(result, RateLimitResult)
        
    @pytest.mark.asyncio
    async def test_rate_limiter_concurrent_requests(self):
        """Test rate limiter behavior under concurrent requests"""
        limiter = create_rate_limiter(default_requests=5, default_window=60)
        key = "concurrent_test_user"
        
        # Send concurrent requests
        tasks = [limiter.is_allowed(key) for _ in range(10)]
        results = await asyncio.gather(*tasks)
        
        # Count allowed vs denied
        allowed_count = sum(1 for r in results if r.allowed)
        denied_count = sum(1 for r in results if not r.allowed)
        
        # Should respect the limit even with concurrent requests
        assert allowed_count <= 5
        assert denied_count >= 5
        
    @pytest.mark.asyncio
    async def test_rate_limiter_time_manipulation(self):
        """Test rate limiter behavior with time changes"""
        limiter = create_rate_limiter(default_requests=2, default_window=1)
        key = "time_test_user"
        
        # Use up limit
        await limiter.is_allowed(key)
        await limiter.is_allowed(key)
        
        # Should be rate limited
        result = await limiter.is_allowed(key)
        assert result.allowed == False
        
        # Mock time advancement
        with patch('time.time', return_value=time.time() + 2):
            # Should be allowed after time advancement
            result = await limiter.is_allowed(key)
            assert result.allowed == True


# Performance test fixtures
@pytest.fixture
def performance_rate_limiter():
    """Rate limiter for performance testing"""
    return create_rate_limiter(
        default_requests=1000,
        default_window=60,
        strategy=RateLimitStrategy.SLIDING_WINDOW
    )


@pytest.fixture
def mock_request():
    """Mock request object for testing"""
    class MockRequest:
        def __init__(self):
            self.client = MockClient()
            self.headers = {}
            
    class MockClient:
        def __init__(self):
            self.host = "127.0.0.1"
            
    return MockRequest()


if __name__ == "__main__":
    # Run tests with pytest
    pytest.main([__file__, "-v"])