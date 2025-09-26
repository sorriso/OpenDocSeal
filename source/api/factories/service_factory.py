"""
Path: infrastructure/source/api/factories/service_factory.py  
Version: 3 - OPTIMIZED CACHING & PERFORMANCE
"""

import logging
import asyncio
import threading
from typing import Optional, Dict, Any, Set
from datetime import datetime, timezone, timedelta
from abc import ABC, abstractmethod

from ..services.interfaces import (
    AuthServiceInterface, BlockchainServiceInterface, 
    StorageServiceInterface, DocumentServiceInterface
)
from ..config import get_settings

logger = logging.getLogger(__name__)
settings = get_settings()


class TestHooks:
    """Test hooks for capturing events and debugging"""
    
    def __init__(self):
        self.events = []
        self._lock = threading.RLock()  # Thread-safe for concurrent access
        
    async def capture_event(self, service: str, event: str, data: Dict[str, Any]):
        """Capture an event for testing"""
        with self._lock:
            event_record = {
                "service": service,
                "event": event,
                "data": data,
                "timestamp": datetime.now(timezone.utc),
                "thread_id": threading.get_ident()
            }
            self.events.append(event_record)
            
            # OPTIMIZED: Limit events to prevent memory bloat
            if len(self.events) > 10000:
                self.events = self.events[-5000:]  # Keep last 5000 events
        
        logger.debug(f"Test event captured: {service}.{event}")
    
    def get_events(self, service: Optional[str] = None, event: Optional[str] = None) -> list:
        """Get captured events with optional filtering"""
        with self._lock:
            events = self.events.copy()
            
        if service:
            events = [e for e in events if e["service"] == service]
        
        if event:
            events = [e for e in events if e["event"] == event]
        
        return events
    
    def clear_events(self):
        """Clear all captured events"""
        with self._lock:
            self.events.clear()
        logger.debug("Test events cleared")
    
    def get_stats(self) -> Dict[str, Any]:
        """Get statistics about captured events"""
        with self._lock:
            events = self.events.copy()
        
        stats = {
            "total_events": len(events),
            "by_service": {},
            "by_event": {},
            "time_range": None
        }
        
        for event in events:
            service = event["service"]
            event_type = event["event"]
            
            stats["by_service"][service] = stats["by_service"].get(service, 0) + 1
            stats["by_event"][event_type] = stats["by_event"].get(event_type, 0) + 1
        
        if events:
            stats["time_range"] = {
                "start": min(e["timestamp"] for e in events).isoformat(),
                "end": max(e["timestamp"] for e in events).isoformat()
            }
        
        return stats


class NoOpTestHooks:
    """No-operation test hooks for production"""
    
    async def capture_event(self, service: str, event: str, data: Dict[str, Any]):
        pass
    
    def get_events(self, service: Optional[str] = None, event: Optional[str] = None) -> list:
        return []
    
    def clear_events(self):
        pass
    
    def get_stats(self) -> Dict[str, Any]:
        return {"total_events": 0, "by_service": {}, "by_event": {}}


class ServiceCache:
    """OPTIMIZED: Thread-safe service cache with TTL and memory management"""
    
    def __init__(self, default_ttl_minutes: int = 60, max_entries: int = 100):
        self._cache: Dict[str, Dict[str, Any]] = {}
        self._lock = threading.RLock()
        self.default_ttl = timedelta(minutes=default_ttl_minutes)
        self.max_entries = max_entries
        self._last_cleanup = datetime.now(timezone.utc)
        self._cleanup_interval = timedelta(minutes=10)
        
    def get(self, key: str) -> Optional[Any]:
        """Get item from cache with TTL check"""
        with self._lock:
            self._maybe_cleanup()
            
            if key not in self._cache:
                return None
            
            entry = self._cache[key]
            
            # Check TTL
            if datetime.now(timezone.utc) > entry['expires_at']:
                del self._cache[key]
                return None
            
            # Update access time for LRU
            entry['last_accessed'] = datetime.now(timezone.utc)
            return entry['value']
    
    def set(self, key: str, value: Any, ttl: Optional[timedelta] = None) -> None:
        """Set item in cache with TTL"""
        with self._lock:
            self._maybe_cleanup()
            
            # OPTIMIZED: Prevent cache bloat
            if len(self._cache) >= self.max_entries and key not in self._cache:
                self._evict_oldest()
            
            expires_at = datetime.now(timezone.utc) + (ttl or self.default_ttl)
            
            self._cache[key] = {
                'value': value,
                'created_at': datetime.now(timezone.utc),
                'last_accessed': datetime.now(timezone.utc),
                'expires_at': expires_at
            }
    
    def remove(self, key: str) -> bool:
        """Remove item from cache"""
        with self._lock:
            return self._cache.pop(key, None) is not None
    
    def clear(self) -> None:
        """Clear all cache entries"""
        with self._lock:
            self._cache.clear()
    
    def _maybe_cleanup(self) -> None:
        """Periodic cleanup of expired entries"""
        now = datetime.now(timezone.utc)
        
        if now - self._last_cleanup < self._cleanup_interval:
            return
        
        expired_keys = []
        for key, entry in self._cache.items():
            if now > entry['expires_at']:
                expired_keys.append(key)
        
        for key in expired_keys:
            del self._cache[key]
        
        self._last_cleanup = now
        
        if expired_keys:
            logger.debug(f"Cleaned up {len(expired_keys)} expired cache entries")
    
    def _evict_oldest(self) -> None:
        """Evict oldest entry when cache is full"""
        if not self._cache:
            return
        
        oldest_key = min(
            self._cache.keys(),
            key=lambda k: self._cache[k]['last_accessed']
        )
        
        del self._cache[oldest_key]
        logger.debug(f"Evicted oldest cache entry: {oldest_key}")
    
    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        with self._lock:
            now = datetime.now(timezone.utc)
            
            total_entries = len(self._cache)
            expired_entries = sum(1 for entry in self._cache.values() if now > entry['expires_at'])
            
            return {
                "total_entries": total_entries,
                "expired_entries": expired_entries,
                "active_entries": total_entries - expired_entries,
                "max_entries": self.max_entries,
                "cache_utilization": round((total_entries / self.max_entries) * 100, 2),
                "default_ttl_minutes": self.default_ttl.total_seconds() / 60,
                "last_cleanup": self._last_cleanup.isoformat()
            }


class ServiceFactory:
    """OPTIMIZED: Service factory with advanced caching and performance optimizations"""
    
    def __init__(self, test_hooks: Optional[TestHooks] = None):
        self.test_hooks = test_hooks or NoOpTestHooks()
        
        # OPTIMIZED: Advanced caching system
        self._cache = ServiceCache(
            default_ttl_minutes=settings.service_cache_ttl_minutes,
            max_entries=100
        )
        
        # OPTIMIZED: Track service creation for debugging
        self._creation_stats = {
            "auth": 0,
            "blockchain": 0,
            "storage": 0,
            "document": 0
        }
        
        # OPTIMIZED: Lazy loading flags
        self._initialized_services: Set[str] = set()
        
        logger.debug("ServiceFactory initialized with optimized caching")
    
    def create_auth_service(self) -> AuthServiceInterface:
        """OPTIMIZED: Create authentication service with advanced caching"""
        cache_key = f"auth_{settings.auth_mode}_{settings.test_mode}"
        
        # Try cache first
        cached_service = self._cache.get(cache_key)
        if cached_service:
            logger.debug(f"Auth service retrieved from cache: {settings.auth_mode}")
            return cached_service
        
        # Create new service
        if settings.auth_mode == "mock" or settings.test_mode:
            service = self._create_mock_auth_service()
        else:
            service = self._create_production_auth_service()
        
        # OPTIMIZED: Cache with appropriate TTL
        ttl = timedelta(minutes=5 if settings.test_mode else 60)
        self._cache.set(cache_key, service, ttl)
        
        self._creation_stats["auth"] += 1
        self._initialized_services.add("auth")
        
        logger.info(f"Created auth service: {settings.auth_mode} (cached)")
        return service
    
    def _create_mock_auth_service(self) -> AuthServiceInterface:
        """Create mock auth service with optimized settings"""
        from ..services.mocks.auth_mock import AuthMockService
        return AuthMockService(
            delay=0.01 if settings.test_mode else settings.auth_mock_delay,
            test_hooks=self.test_hooks
        )
    
    def _create_production_auth_service(self) -> AuthServiceInterface:
        """Create production auth service with optimized settings"""
        from ..services.auth import AuthService
        return AuthService(
            secret_key=settings.secret_key,
            algorithm=settings.algorithm,
            access_token_expire_minutes=settings.access_token_expire_minutes,
            refresh_token_expire_days=settings.refresh_token_expire_days,
            test_hooks=self.test_hooks
        )
    
    def create_blockchain_service(self) -> BlockchainServiceInterface:
        """OPTIMIZED: Create blockchain service with advanced caching"""
        cache_key = f"blockchain_{settings.blockchain_mode}_{settings.test_mode}"
        
        # Try cache first
        cached_service = self._cache.get(cache_key)
        if cached_service:
            logger.debug(f"Blockchain service retrieved from cache: {settings.blockchain_mode}")
            return cached_service
        
        # Create new service
        if settings.blockchain_mode == "mock" or settings.test_mode:
            service = self._create_mock_blockchain_service()
        else:
            service = self._create_production_blockchain_service()
        
        # OPTIMIZED: Cache with appropriate TTL
        ttl = timedelta(minutes=5 if settings.test_mode else 60)
        self._cache.set(cache_key, service, ttl)
        
        self._creation_stats["blockchain"] += 1
        self._initialized_services.add("blockchain")
        
        logger.info(f"Created blockchain service: {settings.blockchain_mode} (cached)")
        return service
    
    def _create_mock_blockchain_service(self) -> BlockchainServiceInterface:
        """Create mock blockchain service with optimized settings"""
        from ..services.mocks.blockchain_mock import BlockchainMockService
        return BlockchainMockService(
            delay=0.01 if settings.test_mode else settings.blockchain_mock_delay,
            success_rate=1.0 if settings.test_mode else settings.blockchain_mock_success_rate,
            test_hooks=self.test_hooks
        )
    
    def _create_production_blockchain_service(self) -> BlockchainServiceInterface:
        """Create production blockchain service with optimized settings"""
        from ..services.blockchain import BlockchainService
        return BlockchainService(
            network=settings.blockchain_network,
            api_url=settings.opentimestamps_api_url,
            timeout=settings.opentimestamps_timeout,
            max_retries=settings.opentimestamps_max_retries,
            test_hooks=self.test_hooks
        )
    
    def create_storage_service(self) -> StorageServiceInterface:
        """OPTIMIZED: Create storage service with advanced caching"""
        cache_key = f"storage_{settings.storage_mode}_{settings.test_mode}"
        
        # Try cache first
        cached_service = self._cache.get(cache_key)
        if cached_service:
            logger.debug(f"Storage service retrieved from cache: {settings.storage_mode}")
            return cached_service
        
        # Create new service
        if settings.storage_mode == "mock" or settings.test_mode:
            service = self._create_mock_storage_service()
        else:
            service = self._create_production_storage_service()
        
        # OPTIMIZED: Cache with appropriate TTL
        ttl = timedelta(minutes=5 if settings.test_mode else 60)
        self._cache.set(cache_key, service, ttl)
        
        self._creation_stats["storage"] += 1
        self._initialized_services.add("storage")
        
        logger.info(f"Created storage service: {settings.storage_mode} (cached)")
        return service
    
    def _create_mock_storage_service(self) -> StorageServiceInterface:
        """Create mock storage service with optimized settings"""
        from ..services.mocks.storage_mock import StorageMockService
        return StorageMockService(
            delay=0.01 if settings.test_mode else settings.storage_mock_delay,
            test_hooks=self.test_hooks
        )
    
    def _create_production_storage_service(self) -> StorageServiceInterface:
        """Create production storage service with optimized settings"""
        from ..services.storage import StorageService
        return StorageService(
            endpoint=settings.minio_endpoint,
            access_key=settings.minio_access_key,
            secret_key=settings.minio_secret_key,
            secure=settings.minio_secure,
            bucket_name=settings.effective_minio_bucket_name,
            region=settings.minio_region,
            test_hooks=self.test_hooks
        )
    
    def create_document_service(self) -> DocumentServiceInterface:
        """OPTIMIZED: Create document service with dependency injection and caching"""
        cache_key = f"document_service_{settings.test_mode}"
        
        # Try cache first
        cached_service = self._cache.get(cache_key)
        if cached_service:
            logger.debug("Document service retrieved from cache")
            return cached_service
        
        # OPTIMIZED: Lazy creation of dependencies
        auth_service = self.create_auth_service()
        blockchain_service = self.create_blockchain_service()  
        storage_service = self.create_storage_service()
        
        from ..services.document import DocumentService
        service = DocumentService(
            auth_service=auth_service,
            blockchain_service=blockchain_service,
            storage_service=storage_service,
            test_hooks=self.test_hooks
        )
        
        # OPTIMIZED: Cache with shorter TTL since it depends on other services
        ttl = timedelta(minutes=5 if settings.test_mode else 30)
        self._cache.set(cache_key, service, ttl)
        
        self._creation_stats["document"] += 1
        self._initialized_services.add("document")
        
        logger.info("Created document service (cached)")
        return service
    
    def get_service_info(self) -> Dict[str, Any]:
        """OPTIMIZED: Get comprehensive information about services and performance"""
        cache_stats = self._cache.get_stats()
        test_hooks_stats = self.test_hooks.get_stats()
        
        return {
            "factory_type": self.__class__.__name__,
            "initialized_services": list(self._initialized_services),
            "creation_stats": self._creation_stats.copy(),
            "configuration": {
                "auth_mode": settings.auth_mode,
                "blockchain_mode": settings.blockchain_mode,
                "storage_mode": settings.storage_mode,
                "test_mode": settings.test_mode
            },
            "cache_performance": cache_stats,
            "test_hooks": test_hooks_stats,
            "optimizations_enabled": True
        }
    
    def clear_cache(self) -> None:
        """OPTIMIZED: Clear service cache with statistics"""
        old_stats = self._cache.get_stats()
        self._cache.clear()
        
        logger.info(f"Service cache cleared: {old_stats['active_entries']} entries removed")
    
    def warmup_services(self) -> None:
        """OPTIMIZED: Pre-create commonly used services for better performance"""
        logger.info("Warming up services...")
        
        start_time = datetime.now(timezone.utc)
        
        # Pre-create services in order of dependency
        self.create_auth_service()
        self.create_blockchain_service()
        self.create_storage_service()
        self.create_document_service()
        
        duration = datetime.now(timezone.utc) - start_time
        
        logger.info(f"Service warmup completed in {duration.total_seconds():.3f}s")
    
    def health_check(self) -> Dict[str, Any]:
        """OPTIMIZED: Factory health check with performance metrics"""
        try:
            cache_stats = self._cache.get_stats()
            
            return {
                "status": "healthy",
                "factory_type": self.__class__.__name__,
                "services_initialized": len(self._initialized_services),
                "cache_health": {
                    "active_entries": cache_stats["active_entries"],
                    "utilization": cache_stats["cache_utilization"],
                    "expired_entries": cache_stats["expired_entries"]
                },
                "creation_stats": self._creation_stats.copy(),
                "test_hooks_active": not isinstance(self.test_hooks, NoOpTestHooks)
            }
            
        except Exception as e:
            logger.error(f"Factory health check failed: {e}")
            return {
                "status": "unhealthy",
                "error": str(e),
                "error_type": type(e).__name__
            }


class TestServiceFactory(ServiceFactory):
    """OPTIMIZED: Test service factory with performance optimizations"""
    
    def __init__(self):
        # OPTIMIZED: Use faster cache settings for tests
        super().__init__(test_hooks=TestHooks())
        
        # Override cache settings for faster tests
        self._cache = ServiceCache(
            default_ttl_minutes=5,  # Shorter TTL for tests
            max_entries=50  # Smaller cache for tests
        )
        
        logger.debug("TestServiceFactory initialized with optimized test caching")
    
    def create_auth_service(self) -> AuthServiceInterface:
        """OPTIMIZED: Create auth service optimized for testing"""
        if not settings.test_mode:
            # In non-test mode, respect configuration
            return super().create_auth_service()
        
        # OPTIMIZED: Always use fast mock in test mode
        cache_key = "auth_test_optimized"
        
        cached_service = self._cache.get(cache_key)
        if cached_service:
            return cached_service
        
        from ..services.mocks.auth_mock import AuthMockService
        service = AuthMockService(
            delay=0.001,  # Ultra-fast for tests
            test_hooks=self.test_hooks
        )
        
        # Cache with short TTL for tests
        self._cache.set(cache_key, service, timedelta(minutes=1))
        
        self._creation_stats["auth"] += 1
        logger.debug("Created optimized test auth service")
        
        return service
    
    def create_blockchain_service(self) -> BlockchainServiceInterface:
        """OPTIMIZED: Create blockchain service optimized for testing"""
        if not settings.test_mode:
            # In non-test mode, respect configuration
            return super().create_blockchain_service()
        
        # OPTIMIZED: Always use fast mock in test mode
        cache_key = "blockchain_test_optimized"
        
        cached_service = self._cache.get(cache_key)
        if cached_service:
            return cached_service
        
        from ..services.mocks.blockchain_mock import BlockchainMockService
        service = BlockchainMockService(
            delay=0.001,  # Ultra-fast for tests
            success_rate=1.0,  # Always succeed in tests
            test_hooks=self.test_hooks
        )
        
        # Cache with short TTL for tests
        self._cache.set(cache_key, service, timedelta(minutes=1))
        
        self._creation_stats["blockchain"] += 1
        logger.debug("Created optimized test blockchain service")
        
        return service
    
    def create_storage_service(self) -> StorageServiceInterface:
        """OPTIMIZED: Create storage service optimized for testing"""
        if not settings.test_mode:
            # In non-test mode, respect configuration
            return super().create_storage_service()
        
        # OPTIMIZED: Always use fast mock in test mode
        cache_key = "storage_test_optimized"
        
        cached_service = self._cache.get(cache_key)
        if cached_service:
            return cached_service
        
        from ..services.mocks.storage_mock import StorageMockService
        service = StorageMockService(
            delay=0.001,  # Ultra-fast for tests
            test_hooks=self.test_hooks
        )
        
        # Cache with short TTL for tests
        self._cache.set(cache_key, service, timedelta(minutes=1))
        
        self._creation_stats["storage"] += 1
        logger.debug("Created optimized test storage service")
        
        return service


# OPTIMIZED: Global factory instances with singleton pattern
_factory_instance: Optional[ServiceFactory] = None
_test_factory_instance: Optional[TestServiceFactory] = None
_factory_lock = threading.RLock()


def get_service_factory() -> ServiceFactory:
    """OPTIMIZED: Get singleton service factory instance"""
    global _factory_instance
    
    with _factory_lock:
        if _factory_instance is None:
            _factory_instance = ServiceFactory()
            
            # OPTIMIZED: Warmup services in production for better performance
            if not settings.test_mode and not settings.debug:
                asyncio.create_task(_factory_instance.warmup_services())
        
        return _factory_instance


def get_test_service_factory() -> TestServiceFactory:
    """OPTIMIZED: Get singleton test service factory instance"""
    global _test_factory_instance
    
    with _factory_lock:
        if _test_factory_instance is None:
            _test_factory_instance = TestServiceFactory()
        
        return _test_factory_instance


def clear_factory_caches() -> None:
    """OPTIMIZED: Clear all factory caches (useful for testing)"""
    global _factory_instance, _test_factory_instance
    
    with _factory_lock:
        if _factory_instance:
            _factory_instance.clear_cache()
        
        if _test_factory_instance:
            _test_factory_instance.clear_cache()
        
        logger.info("All factory caches cleared")


def get_factory_stats() -> Dict[str, Any]:
    """OPTIMIZED: Get comprehensive factory statistics"""
    stats = {
        "production_factory": None,
        "test_factory": None,
        "current_mode": "test" if settings.test_mode else "production"
    }
    
    with _factory_lock:
        if _factory_instance:
            stats["production_factory"] = _factory_instance.get_service_info()
        
        if _test_factory_instance:
            stats["test_factory"] = _test_factory_instance.get_service_info()
    
    return stats


# Export commonly used classes
__all__ = [
    'ServiceFactory',
    'TestServiceFactory', 
    'TestHooks',
    'NoOpTestHooks',
    'ServiceCache',
    'get_service_factory',
    'get_test_service_factory',
    'clear_factory_caches',
    'get_factory_stats'
]