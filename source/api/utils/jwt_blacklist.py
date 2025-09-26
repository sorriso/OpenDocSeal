"""
Path: infrastructure/source/api/utils/jwt_blacklist.py
Version: 1
"""

import asyncio
import logging
import time
from datetime import datetime, timezone, timedelta
from typing import Set, Dict, Optional, Any
from threading import Lock
import json

# Optional Redis support
try:
    import redis.asyncio as redis
    REDIS_AVAILABLE = True
except ImportError:
    redis = None
    REDIS_AVAILABLE = False

logger = logging.getLogger(__name__)


class TokenBlacklist:
    """
    JWT Token blacklist system with memory and Redis backends
    
    Supports both in-memory and Redis storage for revoked tokens.
    Automatically cleans up expired tokens.
    """
    
    def __init__(
        self, 
        redis_url: Optional[str] = None,
        cleanup_interval: int = 3600,  # 1 hour
        max_memory_tokens: int = 10000
    ):
        self.redis_url = redis_url
        self.cleanup_interval = cleanup_interval
        self.max_memory_tokens = max_memory_tokens
        
        # In-memory storage
        self.blacklisted_tokens: Dict[str, float] = {}  # token_jti -> expiry_timestamp
        self.lock = Lock()
        
        # Redis connection (optional)
        self.redis_client: Optional[redis.Redis] = None
        self.redis_available = False
        
        # Cleanup task
        self.cleanup_task: Optional[asyncio.Task] = None
        self._last_cleanup = time.time()
        
        # Initialize Redis if available
        if redis_url and REDIS_AVAILABLE:
            asyncio.create_task(self._init_redis())
    
    async def _init_redis(self):
        """Initialize Redis connection"""
        try:
            self.redis_client = redis.from_url(
                self.redis_url,
                decode_responses=True,
                socket_connect_timeout=5,
                socket_timeout=5,
                retry_on_timeout=True,
                max_connections=10
            )
            
            # Test connection
            await self.redis_client.ping()
            self.redis_available = True
            logger.info("Redis connection established for JWT blacklist")
            
            # Start cleanup task
            self.cleanup_task = asyncio.create_task(self._cleanup_loop())
            
        except Exception as e:
            logger.warning(f"Redis connection failed, using in-memory blacklist: {e}")
            self.redis_available = False
            self.redis_client = None
    
    async def blacklist_token(self, token_jti: str, expiry: datetime) -> bool:
        """
        Add token to blacklist
        
        Args:
            token_jti: JWT ID (jti claim)
            expiry: Token expiry datetime
            
        Returns:
            True if successfully blacklisted
        """
        try:
            expiry_timestamp = expiry.timestamp()
            
            # Store in Redis if available
            if self.redis_available and self.redis_client:
                try:
                    # Use Redis with expiry
                    ttl_seconds = int(expiry_timestamp - time.time())
                    if ttl_seconds > 0:
                        await self.redis_client.setex(
                            f"blacklist:{token_jti}", 
                            ttl_seconds, 
                            "1"
                        )
                        logger.debug(f"Token {token_jti} blacklisted in Redis")
                        return True
                except Exception as e:
                    logger.warning(f"Redis blacklist failed, falling back to memory: {e}")
            
            # Store in memory as fallback
            with self.lock:
                # Cleanup if memory is getting full
                if len(self.blacklisted_tokens) >= self.max_memory_tokens:
                    self._cleanup_expired_memory()
                
                self.blacklisted_tokens[token_jti] = expiry_timestamp
                logger.debug(f"Token {token_jti} blacklisted in memory")
                
            return True
            
        except Exception as e:
            logger.error(f"Failed to blacklist token {token_jti}: {e}")
            return False
    
    async def is_blacklisted(self, token_jti: str) -> bool:
        """
        Check if token is blacklisted
        
        Args:
            token_jti: JWT ID to check
            
        Returns:
            True if token is blacklisted
        """
        try:
            # Check Redis first if available
            if self.redis_available and self.redis_client:
                try:
                    result = await self.redis_client.get(f"blacklist:{token_jti}")
                    if result is not None:
                        logger.debug(f"Token {token_jti} found blacklisted in Redis")
                        return True
                except Exception as e:
                    logger.warning(f"Redis check failed, checking memory: {e}")
            
            # Check memory storage
            with self.lock:
                expiry_timestamp = self.blacklisted_tokens.get(token_jti)
                if expiry_timestamp is not None:
                    # Check if token is still valid (not expired)
                    if time.time() < expiry_timestamp:
                        logger.debug(f"Token {token_jti} found blacklisted in memory")
                        return True
                    else:
                        # Token expired, remove from memory
                        del self.blacklisted_tokens[token_jti]
            
            return False
            
        except Exception as e:
            logger.error(f"Error checking blacklist for token {token_jti}: {e}")
            # Fail safe: assume not blacklisted if we can't check
            return False
    
    async def remove_token(self, token_jti: str) -> bool:
        """
        Remove token from blacklist (for cleanup or manual removal)
        
        Args:
            token_jti: JWT ID to remove
            
        Returns:
            True if successfully removed
        """
        try:
            removed = False
            
            # Remove from Redis if available
            if self.redis_available and self.redis_client:
                try:
                    result = await self.redis_client.delete(f"blacklist:{token_jti}")
                    if result > 0:
                        removed = True
                        logger.debug(f"Token {token_jti} removed from Redis blacklist")
                except Exception as e:
                    logger.warning(f"Redis removal failed: {e}")
            
            # Remove from memory
            with self.lock:
                if token_jti in self.blacklisted_tokens:
                    del self.blacklisted_tokens[token_jti]
                    removed = True
                    logger.debug(f"Token {token_jti} removed from memory blacklist")
            
            return removed
            
        except Exception as e:
            logger.error(f"Failed to remove token {token_jti}: {e}")
            return False
    
    async def blacklist_user_tokens(self, user_id: str, before: Optional[datetime] = None) -> int:
        """
        Blacklist all tokens for a user (useful for logout all sessions)
        
        Args:
            user_id: User ID whose tokens to blacklist  
            before: Only blacklist tokens issued before this time
            
        Returns:
            Number of tokens blacklisted
        """
        # This is a placeholder - in a real implementation, you'd need to store
        # token-to-user mapping or query your token storage
        logger.warning(f"blacklist_user_tokens called for user {user_id} - not implemented")
        return 0
    
    def _cleanup_expired_memory(self):
        """Clean up expired tokens from memory (called with lock held)"""
        current_time = time.time()
        expired_tokens = [
            jti for jti, expiry in self.blacklisted_tokens.items()
            if current_time >= expiry
        ]
        
        for jti in expired_tokens:
            del self.blacklisted_tokens[jti]
        
        if expired_tokens:
            logger.debug(f"Cleaned up {len(expired_tokens)} expired tokens from memory")
    
    async def _cleanup_loop(self):
        """Periodic cleanup loop"""
        while True:
            try:
                await asyncio.sleep(self.cleanup_interval)
                
                # Memory cleanup
                with self.lock:
                    self._cleanup_expired_memory()
                
                # Redis cleanup is automatic via TTL
                logger.debug("JWT blacklist cleanup completed")
                
            except asyncio.CancelledError:
                logger.info("JWT blacklist cleanup task cancelled")
                break
            except Exception as e:
                logger.error(f"Error in blacklist cleanup loop: {e}")
    
    async def get_stats(self) -> Dict[str, Any]:
        """
        Get blacklist statistics
        
        Returns:
            Statistics dictionary
        """
        stats = {
            "redis_available": self.redis_available,
            "memory_tokens": len(self.blacklisted_tokens),
            "cleanup_interval": self.cleanup_interval,
            "max_memory_tokens": self.max_memory_tokens,
            "last_cleanup": self._last_cleanup
        }
        
        if self.redis_available and self.redis_client:
            try:
                # Get Redis info
                redis_info = await self.redis_client.info()
                stats["redis_connected"] = True
                stats["redis_memory_used"] = redis_info.get('used_memory_human', 'unknown')
            except Exception as e:
                stats["redis_connected"] = False
                stats["redis_error"] = str(e)
        
        return stats
    
    async def close(self):
        """Close Redis connection and cleanup"""
        if self.cleanup_task:
            self.cleanup_task.cancel()
            try:
                await self.cleanup_task
            except asyncio.CancelledError:
                pass
        
        if self.redis_client:
            await self.redis_client.close()
            logger.info("Redis connection closed")


# Global blacklist instance
_blacklist_instance: Optional[TokenBlacklist] = None


def get_token_blacklist(redis_url: Optional[str] = None) -> TokenBlacklist:
    """
    Get global token blacklist instance
    
    Args:
        redis_url: Optional Redis URL for persistent storage
        
    Returns:
        TokenBlacklist instance
    """
    global _blacklist_instance
    
    if _blacklist_instance is None:
        _blacklist_instance = TokenBlacklist(redis_url=redis_url)
    
    return _blacklist_instance


async def blacklist_token(token_jti: str, expiry: datetime) -> bool:
    """
    Convenience function to blacklist a token
    
    Args:
        token_jti: JWT ID to blacklist
        expiry: Token expiry time
        
    Returns:
        True if successfully blacklisted
    """
    blacklist = get_token_blacklist()
    return await blacklist.blacklist_token(token_jti, expiry)


async def is_token_blacklisted(token_jti: str) -> bool:
    """
    Convenience function to check if token is blacklisted
    
    Args:
        token_jti: JWT ID to check
        
    Returns:
        True if blacklisted
    """
    blacklist = get_token_blacklist()
    return await blacklist.is_blacklisted(token_jti)