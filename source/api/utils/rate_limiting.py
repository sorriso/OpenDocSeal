"""
Path: infrastructure/source/api/utils/rate_limiting.py
Version: 2
"""

import asyncio
import time
import logging
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List, Optional, Union
from enum import Enum
from dataclasses import dataclass
from threading import Lock
import hashlib
import json

logger = logging.getLogger(__name__)


class RateLimitStrategy(str, Enum):
    """Rate limiting strategies"""
    FIXED_WINDOW = "fixed_window"
    SLIDING_WINDOW = "sliding_window" 
    TOKEN_BUCKET = "token_bucket"
    LEAKY_BUCKET = "leaky_bucket"


@dataclass
class RateLimitRule:
    """Rate limiting rule configuration"""
    requests: int
    window: int  # seconds
    strategy: RateLimitStrategy = RateLimitStrategy.SLIDING_WINDOW
    burst_multiplier: float = 1.0  # For token bucket
    enabled: bool = True
    
    def __post_init__(self):
        """Validate rule parameters"""
        if self.requests <= 0:
            raise ValueError("Requests must be positive")
        if self.window <= 0:
            raise ValueError("Window must be positive")
        if self.burst_multiplier < 1.0:
            raise ValueError("Burst multiplier must be >= 1.0")


@dataclass 
class RateLimitResult:
    """Rate limit check result"""
    allowed: bool
    requests_remaining: int
    reset_time: Optional[datetime] = None
    retry_after: Optional[int] = None  # seconds
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        return {
            "allowed": self.allowed,
            "requests_remaining": self.requests_remaining,
            "reset_time": self.reset_time.isoformat() if self.reset_time else None,
            "retry_after": self.retry_after
        }


class FixedWindowLimiter:
    """Fixed time window rate limiter"""
    
    def __init__(self):
        self.windows: Dict[str, Dict[str, Any]] = {}
        self._lock = Lock()
        self._last_cleanup = time.time()
    
    async def is_allowed(self, key: str, requests: int, window: int) -> RateLimitResult:
        """Check if request is allowed using fixed window"""
        current_time = time.time()
        window_start = int(current_time // window) * window
        window_key = f"{key}:{window_start}"
        
        # Cleanup old windows periodically
        if current_time - self._last_cleanup > 300:  # Every 5 minutes
            await self._cleanup_old_windows(current_time)
        
        with self._lock:
            if window_key not in self.windows:
                self.windows[window_key] = {
                    "count": 0,
                    "window_start": window_start,
                    "window_end": window_start + window
                }
            
            window_data = self.windows[window_key]
            
            # Check if still in current window
            if current_time >= window_data["window_end"]:
                # Reset for new window
                window_data["count"] = 0
                window_data["window_start"] = window_start
                window_data["window_end"] = window_start + window
            
            if window_data["count"] < requests:
                window_data["count"] += 1
                remaining = requests - window_data["count"]
                reset_time = datetime.fromtimestamp(window_data["window_end"], timezone.utc)
                
                return RateLimitResult(
                    allowed=True,
                    requests_remaining=remaining,
                    reset_time=reset_time
                )
            else:
                reset_time = datetime.fromtimestamp(window_data["window_end"], timezone.utc)
                retry_after = int(window_data["window_end"] - current_time)
                
                return RateLimitResult(
                    allowed=False,
                    requests_remaining=0,
                    reset_time=reset_time,
                    retry_after=retry_after
                )
    
    async def _cleanup_old_windows(self, current_time: float):
        """Remove old window data"""
        keys_to_remove = []
        
        with self._lock:
            for key, window_data in self.windows.items():
                if current_time > window_data["window_end"] + 3600:  # 1 hour buffer
                    keys_to_remove.append(key)
            
            for key in keys_to_remove:
                del self.windows[key]
        
        self._last_cleanup = current_time


class SlidingWindowLimiter:
    """Sliding window rate limiter using request timestamps"""
    
    def __init__(self):
        self.requests: Dict[str, List[float]] = {}
        self._lock = Lock()
        self._last_cleanup = time.time()
    
    async def is_allowed(self, key: str, requests: int, window: int) -> RateLimitResult:
        """Check if request is allowed using sliding window"""
        current_time = time.time()
        window_start = current_time - window
        
        # Cleanup old entries periodically
        if current_time - self._last_cleanup > 300:  # Every 5 minutes
            await self._cleanup_old_requests(current_time)
        
        with self._lock:
            if key not in self.requests:
                self.requests[key] = []
            
            request_times = self.requests[key]
            
            # Remove requests outside window
            request_times[:] = [t for t in request_times if t > window_start]
            
            if len(request_times) < requests:
                request_times.append(current_time)
                remaining = requests - len(request_times)
                
                # Calculate reset time (when oldest request in window expires)
                if request_times:
                    oldest_request = min(request_times)
                    reset_time = datetime.fromtimestamp(oldest_request + window, timezone.utc)
                else:
                    reset_time = datetime.fromtimestamp(current_time + window, timezone.utc)
                
                return RateLimitResult(
                    allowed=True,
                    requests_remaining=remaining,
                    reset_time=reset_time
                )
            else:
                # Rate limit exceeded
                oldest_request = min(request_times)
                reset_time = datetime.fromtimestamp(oldest_request + window, timezone.utc)
                retry_after = int((oldest_request + window) - current_time)
                
                return RateLimitResult(
                    allowed=False,
                    requests_remaining=0,
                    reset_time=reset_time,
                    retry_after=max(1, retry_after)
                )
    
    async def _cleanup_old_requests(self, current_time: float):
        """Remove old request data"""
        keys_to_remove = []
        
        with self._lock:
            for key, request_times in self.requests.items():
                # Remove requests older than 1 hour
                cutoff_time = current_time - 3600
                request_times[:] = [t for t in request_times if t > cutoff_time]
                
                # Remove empty entries
                if not request_times:
                    keys_to_remove.append(key)
            
            for key in keys_to_remove:
                del self.requests[key]
        
        self._last_cleanup = current_time


class TokenBucketLimiter:
    """Token bucket rate limiter with burst support"""
    
    def __init__(self):
        self.buckets: Dict[str, Dict[str, Any]] = {}
        self._lock = Lock()
        self._last_cleanup = time.time()
    
    async def is_allowed(self, key: str, requests: int, window: int, burst_multiplier: float = 1.0) -> RateLimitResult:
        """Check if request is allowed using token bucket"""
        current_time = time.time()
        tokens_per_second = requests / window
        max_tokens = int(requests * burst_multiplier)
        
        # Cleanup old buckets periodically
        if current_time - self._last_cleanup > 300:  # Every 5 minutes
            await self._cleanup_old_buckets(current_time)
        
        with self._lock:
            if key not in self.buckets:
                self.buckets[key] = {
                    "tokens": max_tokens,
                    "last_refill": current_time,
                    "max_tokens": max_tokens,
                    "refill_rate": tokens_per_second
                }
            
            bucket = self.buckets[key]
            
            # Refill tokens based on elapsed time
            time_elapsed = current_time - bucket["last_refill"]
            tokens_to_add = time_elapsed * bucket["refill_rate"]
            bucket["tokens"] = min(bucket["max_tokens"], bucket["tokens"] + tokens_to_add)
            bucket["last_refill"] = current_time
            
            if bucket["tokens"] >= 1.0:
                bucket["tokens"] -= 1.0
                remaining = int(bucket["tokens"])
                
                # Calculate reset time (when bucket will be full)
                tokens_needed = bucket["max_tokens"] - bucket["tokens"]
                seconds_to_full = tokens_needed / bucket["refill_rate"]
                reset_time = datetime.fromtimestamp(current_time + seconds_to_full, timezone.utc)
                
                return RateLimitResult(
                    allowed=True,
                    requests_remaining=remaining,
                    reset_time=reset_time
                )
            else:
                # Not enough tokens
                tokens_needed = 1.0 - bucket["tokens"]
                retry_after = int(tokens_needed / bucket["refill_rate"]) + 1
                reset_time = datetime.fromtimestamp(current_time + retry_after, timezone.utc)
                
                return RateLimitResult(
                    allowed=False,
                    requests_remaining=0,
                    reset_time=reset_time,
                    retry_after=retry_after
                )
    
    async def _cleanup_old_buckets(self, current_time: float):
        """Remove inactive buckets"""
        keys_to_remove = []
        
        with self._lock:
            for key, bucket in self.buckets.items():
                if current_time - bucket["last_refill"] > 3600:  # 1 hour inactive
                    keys_to_remove.append(key)
            
            for key in keys_to_remove:
                del self.buckets[key]
        
        self._last_cleanup = current_time


class LeakyBucketLimiter:
    """Leaky bucket rate limiter for smooth request processing"""
    
    def __init__(self):
        self.buckets: Dict[str, Dict[str, Any]] = {}
        self._lock = Lock()
        self._last_cleanup = time.time()
    
    async def is_allowed(self, key: str, requests: int, window: int) -> RateLimitResult:
        """Check if request is allowed using leaky bucket"""
        current_time = time.time()
        leak_rate = requests / window  # requests per second
        bucket_size = requests  # maximum queue size
        
        # Cleanup old buckets periodically
        if current_time - self._last_cleanup > 300:  # Every 5 minutes
            await self._cleanup_old_buckets(current_time)
        
        with self._lock:
            if key not in self.buckets:
                self.buckets[key] = {
                    "level": 0.0,
                    "last_leak": current_time,
                    "bucket_size": bucket_size,
                    "leak_rate": leak_rate
                }
            
            bucket = self.buckets[key]
            
            # Leak tokens based on elapsed time
            time_elapsed = current_time - bucket["last_leak"]
            tokens_leaked = time_elapsed * bucket["leak_rate"]
            bucket["level"] = max(0.0, bucket["level"] - tokens_leaked)
            bucket["last_leak"] = current_time
            
            if bucket["level"] < bucket["bucket_size"]:
                bucket["level"] += 1.0
                remaining = int(bucket["bucket_size"] - bucket["level"])
                
                # Calculate reset time (when bucket will be empty)
                seconds_to_empty = bucket["level"] / bucket["leak_rate"]
                reset_time = datetime.fromtimestamp(current_time + seconds_to_empty, timezone.utc)
                
                return RateLimitResult(
                    allowed=True,
                    requests_remaining=remaining,
                    reset_time=reset_time
                )
            else:
                # Bucket overflow
                overflow = bucket["level"] - bucket["bucket_size"]
                retry_after = int(overflow / bucket["leak_rate"]) + 1
                reset_time = datetime.fromtimestamp(current_time + retry_after, timezone.utc)
                
                return RateLimitResult(
                    allowed=False,
                    requests_remaining=0,
                    reset_time=reset_time,
                    retry_after=retry_after
                )
    
    async def _cleanup_old_buckets(self, current_time: float):
        """Remove old bucket data"""
        keys_to_remove = []
        
        with self._lock:
            for key, bucket in self.buckets.items():
                if current_time - bucket["last_leak"] > 3600:  # 1 hour old
                    keys_to_remove.append(key)
            
            for key in keys_to_remove:
                del self.buckets[key]
        
        self._last_cleanup = current_time


class RateLimiter:
    """Main rate limiter class that coordinates different strategies"""
    
    def __init__(
        self,
        default_requests: int = 100,
        default_window: int = 3600,
        default_strategy: RateLimitStrategy = RateLimitStrategy.SLIDING_WINDOW
    ):
        self.default_requests = default_requests
        self.default_window = default_window
        self.default_strategy = default_strategy
        
        # Initialize strategy implementations
        self.limiters = {
            RateLimitStrategy.FIXED_WINDOW: FixedWindowLimiter(),
            RateLimitStrategy.SLIDING_WINDOW: SlidingWindowLimiter(),
            RateLimitStrategy.TOKEN_BUCKET: TokenBucketLimiter(),
            RateLimitStrategy.LEAKY_BUCKET: LeakyBucketLimiter()
        }
        
        # Custom rules for different patterns
        self.rules: Dict[str, RateLimitRule] = {}
        
        # Statistics tracking
        self.stats = {
            "requests_checked": 0,
            "requests_allowed": 0,
            "requests_denied": 0,
            "last_reset": time.time()
        }
    
    def add_rule(self, pattern: str, rule: RateLimitRule):
        """Add custom rate limiting rule for pattern"""
        if not rule.enabled:
            logger.info(f"Skipping disabled rate limit rule for pattern '{pattern}'")
            return
            
        self.rules[pattern] = rule
        logger.debug(f"Added rate limit rule for pattern '{pattern}': {rule.requests}/{rule.window}s ({rule.strategy.value})")
    
    def remove_rule(self, pattern: str):
        """Remove rate limiting rule"""
        if pattern in self.rules:
            del self.rules[pattern]
            logger.debug(f"Removed rate limit rule for pattern '{pattern}'")
    
    def get_rules(self) -> Dict[str, RateLimitRule]:
        """Get all active rules"""
        return {k: v for k, v in self.rules.items() if v.enabled}
    
    async def is_allowed(
        self,
        key: str,
        requests: Optional[int] = None,
        window: Optional[int] = None,
        strategy: Optional[RateLimitStrategy] = None
    ) -> RateLimitResult:
        """
        Check if request is allowed
        
        Args:
            key: Unique identifier for rate limiting
            requests: Number of requests allowed (uses default if None)
            window: Time window in seconds (uses default if None)
            strategy: Rate limiting strategy (uses default if None)
            
        Returns:
            Rate limit result
        """
        # Update statistics
        self.stats["requests_checked"] += 1
        
        # Check for matching custom rules
        rule = self._get_matching_rule(key)
        if rule and rule.enabled:
            requests = rule.requests
            window = rule.window
            strategy = rule.strategy
            burst_multiplier = rule.burst_multiplier
        else:
            requests = requests or self.default_requests
            window = window or self.default_window
            strategy = strategy or self.default_strategy
            burst_multiplier = 1.0
        
        # Get appropriate limiter
        limiter = self.limiters[strategy]
        
        try:
            # Check rate limit based on strategy
            if strategy == RateLimitStrategy.TOKEN_BUCKET:
                result = await limiter.is_allowed(key, requests, window, burst_multiplier)
            else:
                result = await limiter.is_allowed(key, requests, window)
            
            # Update statistics
            if result.allowed:
                self.stats["requests_allowed"] += 1
            else:
                self.stats["requests_denied"] += 1
            
            return result
            
        except Exception as e:
            logger.error(f"Rate limiter error for key {key}: {e}", exc_info=True)
            # Fail open - allow request if rate limiter fails
            return RateLimitResult(
                allowed=True,
                requests_remaining=requests - 1,
                reset_time=datetime.now(timezone.utc) + timedelta(seconds=window)
            )
    
    def _get_matching_rule(self, key: str) -> Optional[RateLimitRule]:
        """Get matching rule for key"""
        # Try exact match first
        if key in self.rules:
            return self.rules[key]
        
        # Try pattern matching
        for pattern, rule in self.rules.items():
            if pattern in key or key.startswith(pattern):
                return rule
        return None
    
    async def get_statistics(self) -> Dict[str, Any]:
        """Get rate limiter statistics"""
        stats = dict(self.stats)
        
        # Add computed statistics
        uptime = time.time() - stats["last_reset"]
        stats.update({
            "uptime_seconds": uptime,
            "success_rate": (
                self.stats["requests_allowed"] / self.stats["requests_checked"] * 100
                if self.stats["requests_checked"] > 0 else 100.0
            ),
            "denial_rate": (
                self.stats["requests_denied"] / self.stats["requests_checked"] * 100
                if self.stats["requests_checked"] > 0 else 0.0
            ),
            "requests_per_second": (
                self.stats["requests_checked"] / uptime
                if uptime > 0 else 0.0
            ),
            "active_rules": len([r for r in self.rules.values() if r.enabled]),
            "total_rules": len(self.rules),
            "strategies_available": list(self.limiters.keys())
        })
        
        # Add limiter-specific stats
        for strategy_name, limiter in self.limiters.items():
            strategy_stats = {}
            
            if hasattr(limiter, 'windows'):
                strategy_stats["active_windows"] = len(limiter.windows)
            elif hasattr(limiter, 'requests'):
                strategy_stats["active_queues"] = len(limiter.requests)
            elif hasattr(limiter, 'buckets'):
                strategy_stats["active_buckets"] = len(limiter.buckets)
            
            if strategy_stats:
                stats[f"strategy_{strategy_name.value}"] = strategy_stats
        
        return stats
    
    async def reset_statistics(self):
        """Reset rate limiter statistics"""
        old_stats = dict(self.stats)
        self.stats = {
            "requests_checked": 0,
            "requests_allowed": 0,
            "requests_denied": 0,
            "last_reset": time.time()
        }
        
        logger.info(f"Rate limiter statistics reset. Previous stats: {old_stats}")
    
    async def clear_all_data(self):
        """Clear all rate limiting data (useful for testing)"""
        logger.warning("Clearing all rate limiter data")
        
        for limiter in self.limiters.values():
            if hasattr(limiter, 'windows'):
                limiter.windows.clear()
            if hasattr(limiter, 'requests'):
                limiter.requests.clear()
            if hasattr(limiter, 'buckets'):
                limiter.buckets.clear()
        
        await self.reset_statistics()


# Predefined rate limiting rules for different scenarios
RATE_LIMIT_RULES = {
    "api_key": RateLimitRule(
        requests=1000,  # Higher limit for API key users
        window=3600,    # Per hour
        strategy=RateLimitStrategy.TOKEN_BUCKET,
        burst_multiplier=1.2
    ),
    
    "anonymous": RateLimitRule(
        requests=100,   # Lower limit for anonymous users
        window=3600,    # Per hour
        strategy=RateLimitStrategy.SLIDING_WINDOW
    ),
    
    "auth": RateLimitRule(
        requests=5,     # Strict limit for auth endpoints
        window=300,     # Per 5 minutes
        strategy=RateLimitStrategy.FIXED_WINDOW
    ),
    
    "upload": RateLimitRule(
        requests=10,    # Limited uploads
        window=600,     # Per 10 minutes
        strategy=RateLimitStrategy.TOKEN_BUCKET,
        burst_multiplier=1.5
    ),
    
    "verification": RateLimitRule(
        requests=50,    # Reasonable limit for verification
        window=3600,    # Per hour
        strategy=RateLimitStrategy.SLIDING_WINDOW
    ),
    
    "admin": RateLimitRule(
        requests=5000,  # High limit for admin users
        window=3600,    # Per hour
        strategy=RateLimitStrategy.TOKEN_BUCKET,
        burst_multiplier=2.0
    ),
    
    "health_check": RateLimitRule(
        requests=200,   # High frequency health checks
        window=60,      # Per minute
        strategy=RateLimitStrategy.LEAKY_BUCKET
    )
}


def create_rate_limiter(
    default_requests: int = 100,
    default_window: int = 3600,
    default_strategy: RateLimitStrategy = RateLimitStrategy.SLIDING_WINDOW,
    enable_custom_rules: bool = True
) -> RateLimiter:
    """
    Create configured rate limiter instance
    
    Args:
        default_requests: Default requests per window
        default_window: Default window in seconds
        default_strategy: Default limiting strategy
        enable_custom_rules: Whether to enable predefined rules
        
    Returns:
        Configured RateLimiter instance
    """
    limiter = RateLimiter(default_requests, default_window, default_strategy)
    
    if enable_custom_rules:
        for pattern, rule in RATE_LIMIT_RULES.items():
            limiter.add_rule(pattern, rule)
    
    logger.info(f"Rate limiter created with {len(RATE_LIMIT_RULES) if enable_custom_rules else 0} custom rules")
    
    return limiter


# Utility functions
def get_client_identifier(ip_address: str, user_agent: Optional[str] = None) -> str:
    """
    Generate client identifier for rate limiting
    
    Args:
        ip_address: Client IP address
        user_agent: Client user agent
        
    Returns:
        Unique client identifier
    """
    if user_agent:
        # Use hash of IP + user agent for better uniqueness
        combined = f"{ip_address}:{user_agent}"
        hash_value = hashlib.sha256(combined.encode()).hexdigest()[:16]
        return f"client:{hash_value}"
    else:
        return f"ip:{ip_address}"


def get_user_identifier(user_id: str) -> str:
    """
    Generate user identifier for rate limiting
    
    Args:
        user_id: User ID
        
    Returns:
        User rate limit identifier
    """
    return f"user:{user_id}"


def get_api_key_identifier(api_key_hash: str) -> str:
    """
    Generate API key identifier for rate limiting
    
    Args:
        api_key_hash: Hashed API key
        
    Returns:
        API key rate limit identifier
    """
    return f"api_key:{api_key_hash[:16]}"


def get_endpoint_identifier(endpoint: str, method: str = "GET") -> str:
    """
    Generate endpoint-specific identifier for rate limiting
    
    Args:
        endpoint: API endpoint path
        method: HTTP method
        
    Returns:
        Endpoint rate limit identifier
    """
    return f"endpoint:{method}:{endpoint}"


# Export commonly used classes and functions
__all__ = [
    'RateLimiter',
    'RateLimitRule', 
    'RateLimitResult',
    'RateLimitStrategy',
    'FixedWindowLimiter',
    'SlidingWindowLimiter',
    'TokenBucketLimiter',
    'LeakyBucketLimiter',
    'RATE_LIMIT_RULES',
    'create_rate_limiter',
    'get_client_identifier',
    'get_user_identifier',
    'get_api_key_identifier',
    'get_endpoint_identifier'
]