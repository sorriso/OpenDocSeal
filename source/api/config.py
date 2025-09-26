"""
Path: infrastructure/source/api/config.py
Version: 7 - CONNECTION POOLING & PERFORMANCE OPTIMIZATIONS
"""

import os
import secrets
from enum import Enum
from typing import List, Optional, Dict, Any
from functools import lru_cache

from pydantic import BaseSettings, Field, field_validator, computed_field
from pydantic_settings import SettingsConfigDict


class EnvironmentType(str, Enum):
    """Environment type enumeration"""
    DEVELOPMENT = "development"
    TESTING = "testing" 
    STAGING = "staging"
    PRODUCTION = "production"


class Settings(BaseSettings):
    """Application settings with enhanced performance and connection optimizations"""
    
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore"
    )
    
    # Application Configuration
    app_name: str = Field(default="OpenDocSeal API", description="Application name")
    app_version: str = Field(default="2.0.0", description="Application version")
    environment: EnvironmentType = Field(default=EnvironmentType.DEVELOPMENT, description="Environment type")
    debug: bool = Field(default=False, description="Debug mode")
    
    @computed_field
    @property
    def is_production(self) -> bool:
        """Check if running in production environment"""
        return self.environment == EnvironmentType.PRODUCTION
    
    @computed_field  
    @property
    def is_testing(self) -> bool:
        """Check if running in testing environment"""
        return self.environment == EnvironmentType.TESTING
    
    # CRITICAL: Security Configuration - ENHANCED
    secret_key: str = Field(..., min_length=32, description="Secret key for JWT and encryption")
    
    @field_validator('secret_key')
    @classmethod
    def validate_secret_key(cls, v: str) -> str:
        """Enhanced secret key validation with production checks"""
        if not v:
            raise ValueError(
                "SECURITY CRITICAL: SECRET_KEY cannot be empty. "
                "Set a secure SECRET_KEY environment variable or remove it to auto-generate."
            )
        
        if len(v) < 32:
            raise ValueError(
                f"SECURITY CRITICAL: SECRET_KEY must be at least 32 characters long, got {len(v)}"
            )
        
        # Check for common weak patterns
        weak_patterns = [
            "your-super-secret-key-change-this-in-production",
            "change-this-in-production", 
            "default-secret-key",
            "secret-key",
            "my-secret-key",
            "test-secret-key",
            "development-key"
        ]
        
        v_lower = v.lower()
        for pattern in weak_patterns:
            if pattern in v_lower:
                raise ValueError(
                    f"SECURITY CRITICAL: SECRET_KEY contains weak pattern '{pattern}'. "
                    "Use a cryptographically secure random key."
                )
        
        return v
    
    # K8s/Production Security Configuration - ENHANCED
    behind_reverse_proxy: bool = Field(default=True, description="Running behind reverse proxy (K8s ingress)")
    trust_proxy_headers: bool = Field(default=True, description="Trust X-Forwarded-* headers from proxy")
    allowed_hosts: List[str] = Field(default=["*"], description="Allowed host headers")
    
    # SSO Configuration - ENHANCED
    sso_enabled: bool = Field(default=False, description="SSO handled by reverse proxy")
    sso_header_user: str = Field(default="X-Auth-User", description="Header containing authenticated user from SSO")
    sso_header_email: str = Field(default="X-Auth-Email", description="Header containing user email from SSO")
    sso_header_roles: str = Field(default="X-Auth-Roles", description="Header containing user roles from SSO")
    
    # API Documentation Security - ENHANCED
    enable_docs: Optional[bool] = Field(default=None, description="Enable API documentation")
    
    @field_validator('enable_docs')
    @classmethod
    def validate_docs_security(cls, v: Optional[bool], info) -> bool:
        """Disable docs in production regardless of debug setting"""
        if v is None:
            env = info.data.get('environment', EnvironmentType.DEVELOPMENT)
            return env in [EnvironmentType.DEVELOPMENT, EnvironmentType.TESTING]
        
        env = info.data.get('environment', EnvironmentType.DEVELOPMENT)
        if env == EnvironmentType.PRODUCTION and v:
            raise ValueError(
                "SECURITY CRITICAL: API documentation cannot be enabled in production. "
                "Set ENABLE_DOCS=false or remove the setting."
            )
        
        return v
    
    # JWT Configuration - ENHANCED
    jwt_algorithm: str = Field(default="HS256", description="JWT signing algorithm")
    jwt_access_token_expire_minutes: int = Field(default=30, ge=1, le=480, description="Access token expiration")
    jwt_refresh_token_expire_days: int = Field(default=7, ge=1, le=90, description="Refresh token expiration")
    jwt_blacklist_enabled: bool = Field(default=True, description="Enable JWT token blacklist")
    refresh_token_rotation: bool = Field(default=True, description="Enable refresh token rotation")
    
    # OPTIMIZED: Database Configuration with Performance Tuning
    mongodb_url: str = Field(..., description="MongoDB connection URL")
    mongodb_db_name: str = Field(default="opendocseal", description="MongoDB database name")
    
    # OPTIMIZED: Connection Pool Settings for High Performance
    mongodb_max_connections: int = Field(
        default=100, 
        ge=10, 
        le=500, 
        description="MongoDB max connections (optimized for production load)"
    )
    mongodb_min_connections: int = Field(
        default=10, 
        ge=5, 
        le=50, 
        description="MongoDB min connections (always available)"
    )
    
    # OPTIMIZED: Connection Timeout Settings for Better Responsiveness
    mongodb_connect_timeout_ms: int = Field(
        default=10000,  # Reduced from 20s to 10s for faster failure detection
        ge=5000, 
        le=30000, 
        description="MongoDB connection timeout in milliseconds"
    )
    mongodb_server_selection_timeout_ms: int = Field(
        default=15000,  # Reduced from 30s to 15s for faster failure detection
        ge=5000, 
        le=30000, 
        description="MongoDB server selection timeout in milliseconds"
    )
    mongodb_socket_timeout_ms: int = Field(
        default=30000,  # Explicit 30s socket timeout
        ge=10000, 
        le=60000, 
        description="MongoDB socket timeout in milliseconds"
    )
    mongodb_heartbeat_frequency_ms: int = Field(
        default=10000, 
        ge=5000, 
        le=30000, 
        description="MongoDB heartbeat frequency in milliseconds"
    )
    
    # OPTIMIZED: Advanced MongoDB Performance Settings
    mongodb_max_idle_time_ms: int = Field(
        default=300000,  # 5 minutes - close idle connections for efficiency
        ge=60000,
        le=600000,
        description="MongoDB max idle time for connections"
    )
    mongodb_wait_queue_timeout_ms: int = Field(
        default=10000,  # 10 seconds max wait for connection from pool
        ge=1000,
        le=30000,
        description="MongoDB connection pool wait timeout"
    )
    mongodb_max_connecting: int = Field(
        default=10,  # Limit concurrent connection attempts
        ge=2,
        le=50,
        description="MongoDB max concurrent connection attempts"
    )
    
    # OPTIMIZED: Write and Read Concern Performance Settings
    mongodb_write_concern_w: str = Field(
        default="majority",
        description="MongoDB write concern (majority for consistency, 1 for speed)"
    )
    mongodb_write_concern_timeout_ms: int = Field(
        default=10000,  # 10 second write timeout
        ge=1000,
        le=30000,
        description="MongoDB write concern timeout"
    )
    mongodb_read_concern_level: str = Field(
        default="majority",  # For consistency, use "local" for speed
        description="MongoDB read concern level"
    )
    mongodb_read_preference: str = Field(
        default="primaryPreferred",  # Better performance than "primary"
        description="MongoDB read preference"
    )
    
    @computed_field
    @property
    def mongodb_connection_params(self) -> Dict[str, Any]:
        """OPTIMIZED: Get optimized MongoDB connection parameters"""
        params = {
            # Connection pool optimization
            "maxPoolSize": self.mongodb_max_connections,
            "minPoolSize": self.mongodb_min_connections,
            "maxIdleTimeMS": self.mongodb_max_idle_time_ms,
            "waitQueueTimeoutMS": self.mongodb_wait_queue_timeout_ms,
            "maxConnecting": self.mongodb_max_connecting,
            
            # Timeout optimization
            "connectTimeoutMS": self.mongodb_connect_timeout_ms,
            "serverSelectionTimeoutMS": self.mongodb_server_selection_timeout_ms,
            "socketTimeoutMS": self.mongodb_socket_timeout_ms,
            "heartbeatFrequencyMS": self.mongodb_heartbeat_frequency_ms,
            
            # Performance optimization
            "retryWrites": True,
            "retryReads": True,
            "compressors": ["snappy", "zlib"],
            
            # Write concern
            "w": self.mongodb_write_concern_w,
            "wTimeoutMS": self.mongodb_write_concern_timeout_ms,
            "journal": True,
            
            # Read preference for better performance
            "readPreference": self.mongodb_read_preference,
        }
        
        # OPTIMIZED: Adjust settings based on environment
        if self.is_production:
            # Production: Optimize for consistency and reliability
            params.update({
                "retryWrites": True,
                "retryReads": True,
                "w": "majority",
                "readConcern": {"level": "majority"}
            })
        elif self.is_testing:
            # Testing: Optimize for speed
            params.update({
                "maxPoolSize": 20,  # Smaller pool for tests
                "minPoolSize": 5,
                "w": 1,  # Faster writes
                "readPreference": "primary",
                "connectTimeoutMS": 5000,  # Faster connection timeout
                "serverSelectionTimeoutMS": 5000
            })
        else:
            # Development: Balance speed and reliability
            params.update({
                "w": "majority",
                "readPreference": "primaryPreferred"
            })
        
        return params
    
    @computed_field
    @property
    def effective_mongodb_db_name(self) -> str:
        """Get effective database name with test suffix if needed"""
        if self.test_mode:
            return f"{self.mongodb_db_name}{self.test_database_suffix}"
        return self.mongodb_db_name
    
    # OPTIMIZED: MinIO/S3 Storage Configuration with Connection Pooling
    minio_endpoint: str = Field(..., description="MinIO endpoint")
    minio_access_key: str = Field(..., description="MinIO access key")
    minio_secret_key: str = Field(..., description="MinIO secret key")
    minio_secure: bool = Field(default=True, description="Use HTTPS for MinIO")
    minio_region: str = Field(default="us-east-1", description="MinIO region")
    minio_bucket_name: str = Field(default="opendocseal", description="MinIO bucket name")
    
    # OPTIMIZED: MinIO Connection Pool Settings
    minio_max_connections: int = Field(
        default=20,
        ge=5,
        le=100,
        description="MinIO HTTP connection pool size"
    )
    minio_connection_timeout: int = Field(
        default=10,
        ge=5,
        le=60,
        description="MinIO connection timeout in seconds"
    )
    minio_read_timeout: int = Field(
        default=60,
        ge=10,
        le=300,
        description="MinIO read timeout in seconds"
    )
    minio_retry_attempts: int = Field(
        default=3,
        ge=1,
        le=10,
        description="MinIO retry attempts on failure"
    )
    
    @computed_field
    @property
    def effective_minio_bucket_name(self) -> str:
        """Get effective bucket name with test suffix if needed"""
        if self.test_mode:
            return f"{self.minio_bucket_name}{self.test_bucket_suffix}"
        return self.minio_bucket_name
    
    # File Upload Security - ENHANCED CRITICAL SECURITY FEATURES
    max_file_size: int = Field(default=100*1024*1024, description="Maximum file size in bytes (100MB)")
    allowed_file_types: List[str] = Field(
        default=[
            "application/pdf",
            "application/msword", 
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            "text/plain",
            "image/jpeg",
            "image/png",
            "image/webp"
        ],
        description="Allowed MIME types for file uploads"
    )
    file_scan_enabled: bool = Field(default=True, description="Enable file scanning for malware")
    file_quarantine_suspicious: bool = Field(default=True, description="Quarantine suspicious files")
    file_quarantine_path: Optional[str] = Field(default=None, description="Path for quarantined files")
    
    # Blockchain Configuration - OPTIMIZED
    blockchain_network: str = Field(default="testnet", description="Blockchain network")
    opentimestamps_api_url: str = Field(
        default="https://alice.btc.calendar.opentimestamps.org",
        description="OpenTimestamps API URL"
    )
    # OPTIMIZED: Blockchain timeout settings for better performance
    opentimestamps_timeout: int = Field(
        default=30, 
        ge=10, 
        le=120, 
        description="OpenTimestamps request timeout (optimized)"
    )
    opentimestamps_max_retries: int = Field(
        default=3, 
        ge=1, 
        le=5, 
        description="OpenTimestamps max retries"
    )
    opentimestamps_retry_delay: float = Field(
        default=1.0,
        ge=0.1,
        le=10.0,
        description="OpenTimestamps retry delay in seconds"
    )
    
    # OPTIMIZED: Rate Limiting Configuration for Performance
    rate_limit_enabled: bool = Field(default=True, description="Enable application-level rate limiting")
    rate_limit_requests: int = Field(
        default=1000, 
        ge=100, 
        le=10000, 
        description="Default requests per window"
    )
    rate_limit_window: int = Field(
        default=3600, 
        ge=60, 
        le=86400, 
        description="Rate limit window in seconds"
    )
    rate_limit_trust_forwarded: bool = Field(default=True, description="Trust X-Forwarded-For for rate limiting")
    
    # OPTIMIZED: Advanced Rate Limiting Settings
    rate_limit_storage_uri: Optional[str] = Field(
        default=None,
        description="Redis URI for rate limiting storage (memory if None)"
    )
    rate_limit_key_generator: str = Field(
        default="ip_user_agent",
        description="Key generation strategy for rate limiting"
    )
    rate_limit_strategy: str = Field(
        default="sliding_window",
        description="Rate limiting strategy: sliding_window, fixed_window, token_bucket"
    )
    
    # Security Headers - ADAPTED FOR REVERSE PROXY
    security_headers_enabled: bool = Field(default=False, description="Enable security headers")
    cors_enabled: bool = Field(default=False, description="Enable CORS")
    cors_origins: List[str] = Field(default=["*"], description="Allowed CORS origins")
    
    # OPTIMIZED: Logging Configuration for Performance
    log_level: str = Field(default="INFO", description="Logging level")
    log_file: Optional[str] = Field(default=None, description="Log file path")
    log_format: str = Field(default="json", description="Log format")
    log_correlation: bool = Field(default=True, description="Enable correlation logging")
    log_max_size: int = Field(default=10*1024*1024, description="Max log file size in bytes")
    log_backup_count: int = Field(default=5, description="Number of log backup files")
    
    # OPTIMIZED: Async and Performance Settings
    async_timeout: int = Field(
        default=300,
        ge=30,
        le=600,
        description="Default async operation timeout in seconds"
    )
    thread_pool_max_workers: int = Field(
        default=10,
        ge=2,
        le=50,
        description="Max workers for thread pool executor"
    )
    
    # OPTIMIZED: Caching Configuration
    service_cache_enabled: bool = Field(default=True, description="Enable service factory caching")
    service_cache_ttl_minutes: int = Field(
        default=60,
        ge=1,
        le=1440,
        description="Service cache TTL in minutes"
    )
    query_cache_enabled: bool = Field(default=True, description="Enable database query caching")
    query_cache_ttl_seconds: int = Field(
        default=300,
        ge=30,
        le=3600,
        description="Query cache TTL in seconds"
    )
    
    # Security Monitoring - ENHANCED
    security_monitoring_enabled: bool = Field(default=True, description="Enable security event monitoring")
    failed_auth_threshold: int = Field(default=5, ge=1, le=50, description="Failed authentication threshold")
    failed_auth_window: int = Field(default=300, ge=60, le=3600, description="Failed authentication window in seconds")
    suspicious_activity_alert: bool = Field(default=True, description="Enable suspicious activity alerts")
    
    # Test Configuration
    test_mode: bool = Field(default=False, description="Enable test mode")
    test_cleanup_on_exit: bool = Field(default=True, description="Cleanup test data on exit")
    test_correlation_enabled: bool = Field(default=True, description="Enable request correlation in tests")
    test_database_suffix: str = Field(default="_test", description="Test database suffix")
    test_bucket_suffix: str = Field(default="-test", description="Test MinIO bucket suffix")
    
    # OPTIMIZED: Redis Configuration for Performance
    redis_url: Optional[str] = Field(default=None, description="Redis connection URL")
    redis_enabled: bool = Field(default=False, description="Enable Redis integration")
    redis_max_connections: int = Field(
        default=20,
        ge=5,
        le=100,
        description="Redis connection pool size"
    )
    redis_connection_timeout: int = Field(
        default=10,
        ge=1,
        le=60,
        description="Redis connection timeout in seconds"
    )
    redis_socket_timeout: int = Field(
        default=30,
        ge=5,
        le=120,
        description="Redis socket timeout in seconds"
    )
    redis_retry_attempts: int = Field(
        default=3,
        ge=1,
        le=10,
        description="Redis retry attempts"
    )
    
    # OPTIMIZED: Service Mode Configuration for Performance
    auth_mode: str = Field(default="production", description="Auth service mode")
    blockchain_mode: str = Field(default="production", description="Blockchain service mode") 
    storage_mode: str = Field(default="production", description="Storage service mode")
    
    # OPTIMIZED: Mock Service Performance Settings (for development/testing)
    auth_mock_delay: float = Field(default=0.1, ge=0.0, le=5.0, description="Auth mock service delay")
    blockchain_mock_delay: float = Field(default=0.2, ge=0.0, le=5.0, description="Blockchain mock service delay")
    storage_mock_delay: float = Field(default=0.1, ge=0.0, le=5.0, description="Storage mock service delay")
    blockchain_mock_success_rate: float = Field(
        default=0.95, 
        ge=0.1, 
        le=1.0, 
        description="Blockchain mock success rate"
    )
    
    # OPTIMIZED: Performance Monitoring Settings
    enable_metrics: bool = Field(default=True, description="Enable performance metrics collection")
    metrics_export_interval: int = Field(
        default=60,
        ge=10,
        le=300,
        description="Metrics export interval in seconds"
    )
    slow_query_threshold_ms: int = Field(
        default=1000,
        ge=100,
        le=10000,
        description="Slow query detection threshold in milliseconds"
    )
    
    # Performance Configuration Validation
    def validate_performance_configuration(self) -> Dict[str, Any]:
        """Validate performance configuration settings"""
        issues = []
        warnings = []
        recommendations = []
        
        # Database performance checks
        if self.mongodb_max_connections < 50 and self.is_production:
            warnings.append("Low MongoDB max connections for production (recommend 100+)")
        
        if self.mongodb_connect_timeout_ms > 15000:
            warnings.append("High MongoDB connection timeout may impact responsiveness")
        
        if self.mongodb_write_concern_w == "1" and self.is_production:
            warnings.append("Write concern 'w=1' reduces durability guarantees in production")
        
        # Cache configuration checks
        if not self.service_cache_enabled and self.is_production:
            warnings.append("Service caching disabled - may impact performance")
        
        if self.service_cache_ttl_minutes < 15 and self.is_production:
            recommendations.append("Consider longer service cache TTL in production")
        
        # Connection pool optimization checks
        if self.minio_max_connections < 10 and self.is_production:
            warnings.append("Low MinIO connection pool size for production")
        
        # Thread pool checks
        if self.thread_pool_max_workers < 5:
            warnings.append("Low thread pool size may limit concurrent I/O operations")
        
        # Rate limiting performance
        if not self.rate_limit_enabled:
            warnings.append("Rate limiting disabled - DDoS vulnerability")
        
        # Redis performance checks
        if self.redis_enabled:
            if self.redis_max_connections < 10:
                recommendations.append("Consider increasing Redis connection pool for better performance")
        
        return {
            "valid": len(issues) == 0,
            "performance_score": max(0, 10 - len(issues) * 2 - len(warnings)),
            "critical_issues": issues,
            "warnings": warnings,
            "recommendations": recommendations
        }
    
    def get_performance_summary(self) -> Dict[str, Any]:
        """Get performance configuration summary"""
        return {
            "environment": self.environment,
            "database_performance": {
                "max_connections": self.mongodb_max_connections,
                "connection_timeout_ms": self.mongodb_connect_timeout_ms,
                "write_concern": self.mongodb_write_concern_w,
                "read_preference": self.mongodb_read_preference,
                "pool_optimization": True
            },
            "storage_performance": {
                "max_connections": self.minio_max_connections,
                "connection_timeout": self.minio_connection_timeout,
                "retry_attempts": self.minio_retry_attempts,
                "streaming_enabled": True
            },
            "caching": {
                "service_cache_enabled": self.service_cache_enabled,
                "service_cache_ttl_minutes": self.service_cache_ttl_minutes,
                "query_cache_enabled": self.query_cache_enabled,
                "redis_enabled": self.redis_enabled
            },
            "async_settings": {
                "default_timeout": self.async_timeout,
                "thread_pool_workers": self.thread_pool_max_workers,
                "metrics_enabled": self.enable_metrics
            },
            "rate_limiting": {
                "enabled": self.rate_limit_enabled,
                "strategy": self.rate_limit_strategy,
                "requests_per_window": self.rate_limit_requests
            }
        }


@lru_cache()
def get_settings() -> Settings:
    """Get cached settings instance for better performance"""
    return Settings()


# Export for backward compatibility
settings = get_settings()