"""
Path: infrastructure/source/api/utils/logging.py
Version: 2
"""

import logging
import logging.handlers
import json
import sys
import traceback
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Union, TYPE_CHECKING
from pathlib import Path
from contextvars import ContextVar
from contextlib import contextmanager
import functools
import time

# FIXED: Conditional import for structlog 25.4.0+ compatibility
try:
    import structlog
    from structlog import configure, contextvars
    STRUCTLOG_AVAILABLE = True
except ImportError:
    STRUCTLOG_AVAILABLE = False
    structlog = None
    contextvars = None

# Context variable for correlation tracking
correlation_context: ContextVar[Optional[str]] = ContextVar('correlation_id', default=None)


class JSONFormatter(logging.Formatter):
    """JSON formatter for structured logging in production"""
    
    def __init__(self, *args, **kwargs):
        super().__init__()
        self.default_fields = {
            'service': 'opendocseal-api',
            'environment': 'production',
            'version': '1.0.0'
        }
    
    def format(self, record: logging.LogRecord) -> str:
        """Format log record as JSON"""
        # Base log entry
        log_entry = {
            'timestamp': datetime.fromtimestamp(record.created, timezone.utc).isoformat(),
            'level': record.levelname,
            'logger': record.name,
            'message': record.getMessage(),
            'module': record.module,
            'function': record.funcName,
            'line': record.lineno,
            **self.default_fields
        }
        
        # Add correlation ID if available
        correlation_id = correlation_context.get()
        if correlation_id:
            log_entry['correlation_id'] = correlation_id
        
        # Add structlog context if available
        if STRUCTLOG_AVAILABLE and contextvars:
            try:
                # FIXED: Compatible with structlog 25.4.0+
                structlog_context = contextvars.get_contextvars()
                if structlog_context:
                    log_entry.update(structlog_context)
            except (AttributeError, TypeError):
                # Fallback for older structlog versions
                pass
        
        # Add exception information if present
        if record.exc_info:
            log_entry['exception'] = {
                'type': record.exc_info[0].__name__,
                'message': str(record.exc_info[1]),
                'traceback': traceback.format_exception(*record.exc_info)
            }
        
        # Add extra fields from LoggerAdapter or direct logging calls
        if hasattr(record, '__dict__'):
            for key, value in record.__dict__.items():
                if key not in ['name', 'msg', 'args', 'levelname', 'levelno', 
                              'pathname', 'filename', 'module', 'lineno', 
                              'funcName', 'created', 'msecs', 'relativeCreated', 
                              'thread', 'threadName', 'processName', 'process', 
                              'exc_info', 'exc_text', 'stack_info']:
                    log_entry[key] = value
        
        return json.dumps(log_entry, default=str, ensure_ascii=False)


class TextFormatter(logging.Formatter):
    """Human-readable text formatter for development"""
    
    def __init__(self, *args, **kwargs):
        # FIXED: Enhanced format string with more context
        format_string = (
            "%(asctime)s | %(levelname)-8s | %(name)-20s | "
            "%(funcName)-15s:%(lineno)-4d | %(message)s"
        )
        super().__init__(format_string, datefmt='%Y-%m-%d %H:%M:%S')
    
    def format(self, record: logging.LogRecord) -> str:
        """Format log record with correlation ID"""
        formatted = super().format(record)
        
        # Add correlation ID if available
        correlation_id = correlation_context.get()
        if correlation_id:
            formatted = f"[{correlation_id[:8]}] {formatted}"
        
        return formatted


class CorrelatedLogger:
    """Logger wrapper that automatically includes correlation ID"""
    
    def __init__(self, logger: logging.Logger, correlation_id: Optional[str] = None):
        self.logger = logger
        self.correlation_id = correlation_id
    
    def _log(self, level: int, message: str, *args, **kwargs):
        """Internal log method with correlation"""
        extra = kwargs.get('extra', {})
        
        # Add correlation ID
        if self.correlation_id:
            extra['correlation_id'] = self.correlation_id
        elif correlation_context.get():
            extra['correlation_id'] = correlation_context.get()
        
        kwargs['extra'] = extra
        self.logger.log(level, message, *args, **kwargs)
    
    def debug(self, message, *args, **kwargs):
        self._log(logging.DEBUG, message, *args, **kwargs)
    
    def info(self, message, *args, **kwargs):
        self._log(logging.INFO, message, *args, **kwargs)
    
    def warning(self, message, *args, **kwargs):
        self._log(logging.WARNING, message, *args, **kwargs)
    
    def error(self, message, *args, **kwargs):
        self._log(logging.ERROR, message, *args, **kwargs)
    
    def critical(self, message, *args, **kwargs):
        self._log(logging.CRITICAL, message, *args, **kwargs)
    
    def exception(self, message, *args, **kwargs):
        kwargs['exc_info'] = True
        self._log(logging.ERROR, message, *args, **kwargs)


class CorrelatedTimedLogger(CorrelatedLogger):
    """Correlated logger with automatic timing capabilities"""
    
    def timed_operation(self, operation_name: str):
        """Context manager for timing operations"""
        return TimedOperationContext(self, operation_name)


class TimedOperationContext:
    """Context manager for timed operations"""
    
    def __init__(self, logger: CorrelatedLogger, operation_name: str):
        self.logger = logger
        self.operation_name = operation_name
        self.start_time = None
    
    def __enter__(self):
        self.start_time = time.time()
        self.logger.debug(f"Starting operation: {self.operation_name}")
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        duration = time.time() - self.start_time
        if exc_type:
            self.logger.error(
                f"Operation failed: {self.operation_name} ({duration:.3f}s)",
                extra={'operation': self.operation_name, 'duration': duration, 'failed': True}
            )
        else:
            self.logger.info(
                f"Operation completed: {self.operation_name} ({duration:.3f}s)",
                extra={'operation': self.operation_name, 'duration': duration, 'success': True}
            )


class LoggerMixin:
    """Mixin to add logging capabilities to any class"""
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._logger = None
    
    @property
    def logger(self) -> CorrelatedLogger:
        if self._logger is None:
            base_logger = logging.getLogger(f"{self.__class__.__module__}.{self.__class__.__name__}")
            self._logger = CorrelatedLogger(base_logger)
        return self._logger


def setup_logging(
    log_level: str = "INFO",
    log_file: Optional[str] = None,
    json_format: bool = False,
    max_file_size: int = 10 * 1024 * 1024,  # 10MB
    backup_count: int = 5,
    enable_console: bool = True,
    correlation_enabled: bool = True,
    setup_structlog: bool = True
) -> None:
    """
    Set up comprehensive logging configuration
    
    Args:
        log_level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_file: Path to log file (optional)
        json_format: Use JSON formatting (recommended for production)
        max_file_size: Maximum log file size before rotation
        backup_count: Number of backup files to keep
        enable_console: Enable console output
        correlation_enabled: Enable correlation ID tracking
        setup_structlog: Configure structlog if available
    """
    # Convert string level to logging level
    numeric_level = getattr(logging, log_level.upper(), logging.INFO)
    
    # Create root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(numeric_level)
    
    # Clear existing handlers
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)
    
    # Choose formatter
    formatter = JSONFormatter() if json_format else TextFormatter()
    
    # Console handler
    if enable_console:
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(numeric_level)
        console_handler.setFormatter(formatter)
        root_logger.addHandler(console_handler)
    
    # File handler with rotation
    if log_file:
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        
        file_handler = logging.handlers.RotatingFileHandler(
            filename=log_file,
            maxBytes=max_file_size,
            backupCount=backup_count,
            encoding='utf-8'
        )
        file_handler.setLevel(numeric_level)
        file_handler.setFormatter(formatter)
        root_logger.addHandler(file_handler)
    
    # FIXED: Setup structlog 25.4.0+ if available and requested
    if setup_structlog and STRUCTLOG_AVAILABLE:
        try:
            # Configure structlog with enhanced compatibility
            configure(
                processors=[
                    contextvars.merge_contextvars,  # Add context variables
                    structlog.stdlib.filter_by_level,
                    structlog.stdlib.add_logger_name,
                    structlog.stdlib.add_log_level,
                    structlog.stdlib.PositionalArgumentsFormatter(),
                    structlog.processors.StackInfoRenderer(),
                    structlog.processors.format_exc_info,
                    structlog.processors.UnicodeDecoder(),
                    structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
                ],
                logger_factory=structlog.stdlib.LoggerFactory(),
                wrapper_class=structlog.stdlib.BoundLogger,
                cache_logger_on_first_use=True,
            )
            
            # Create structlog-compatible formatter for stdlib integration
            if json_format:
                structlog_processor = structlog.processors.JSONRenderer()
            else:
                structlog_processor = structlog.dev.ConsoleRenderer()
            
            # Update handlers to use structlog processor
            structlog_formatter = structlog.stdlib.ProcessorFormatter(
                processor=structlog_processor,
            )
            
            for handler in root_logger.handlers:
                handler.setFormatter(structlog_formatter)
                
        except Exception as e:
            # Fallback to standard logging if structlog setup fails
            print(f"Warning: Failed to setup structlog: {e}")
            print("Falling back to standard logging")
    
    # Configure third-party loggers to be less verbose
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("requests").setLevel(logging.WARNING)
    logging.getLogger("motor").setLevel(logging.WARNING)
    logging.getLogger("pymongo").setLevel(logging.WARNING)
    logging.getLogger("minio").setLevel(logging.WARNING)
    
    # Log configuration
    config_logger = logging.getLogger(__name__)
    config_logger.info(f"Logging configured - Level: {log_level}, JSON: {json_format}, File: {log_file}")
    if STRUCTLOG_AVAILABLE and setup_structlog:
        config_logger.info(f"Structlog {structlog.__version__} configured successfully")


def get_logger(name: str, correlation_enabled: bool = True) -> Union[logging.Logger, CorrelatedLogger]:
    """
    Get a logger instance
    
    Args:
        name: Logger name (usually __name__)
        correlation_enabled: Enable correlation tracking
        
    Returns:
        Logger instance (correlated if enabled)
    """
    base_logger = logging.getLogger(name)
    
    if correlation_enabled:
        return CorrelatedLogger(base_logger)
    else:
        return base_logger


def set_correlation_context(correlation_id: str) -> None:
    """Set correlation ID for current context"""
    correlation_context.set(correlation_id)
    
    # Also set in structlog if available
    if STRUCTLOG_AVAILABLE and contextvars:
        try:
            contextvars.bind_contextvars(correlation_id=correlation_id)
        except Exception:
            # Ignore errors if contextvars doesn't work as expected
            pass


def clear_correlation_context() -> None:
    """Clear correlation ID from current context"""
    correlation_context.set(None)
    
    # Also clear in structlog if available
    if STRUCTLOG_AVAILABLE and contextvars:
        try:
            contextvars.clear_contextvars()
        except Exception:
            # Ignore errors if contextvars doesn't work as expected
            pass


def get_correlation_context() -> Optional[str]:
    """Get current correlation ID"""
    return correlation_context.get()


@contextmanager
def correlation_context_manager(correlation_id: str):
    """Context manager for temporary correlation ID"""
    token = correlation_context.set(correlation_id)
    try:
        # Also set in structlog if available
        if STRUCTLOG_AVAILABLE and contextvars:
            contextvars.bind_contextvars(correlation_id=correlation_id)
        yield correlation_id
    finally:
        correlation_context.reset(token)
        if STRUCTLOG_AVAILABLE and contextvars:
            try:
                contextvars.clear_contextvars()
            except Exception:
                pass


# FIXED: Enhanced decorator with better compatibility
def timed_operation(
    logger: Optional[logging.Logger] = None,
    operation_name: Optional[str] = None,
    level: int = logging.INFO,
    include_args: bool = False,
    slow_threshold: float = 1.0
):
    """
    Decorator to automatically log operation timing
    
    Args:
        logger: Logger to use (defaults to function's module logger)
        operation_name: Name of operation (defaults to function name)
        level: Log level to use
        include_args: Include function arguments in log
        slow_threshold: Threshold for warning about slow operations
    """
    def decorator(func):
        @functools.wraps(func)
        def sync_wrapper(*args, **kwargs):
            nonlocal logger, operation_name
            
            if logger is None:
                logger = logging.getLogger(func.__module__)
            
            if operation_name is None:
                operation_name = func.__name__
            
            start_time = time.time()
            
            try:
                result = func(*args, **kwargs)
                duration = time.time() - start_time
                
                # Log completion
                extra = {'operation': operation_name, 'duration_seconds': duration}
                
                if include_args and args:
                    extra['args_count'] = len(args)
                if include_args and kwargs:
                    extra['kwargs_keys'] = list(kwargs.keys())
                
                if duration > slow_threshold:
                    logger.warning(
                        f"{operation_name} completed slowly in {duration:.3f}s",
                        extra=extra
                    )
                else:
                    logger.log(
                        level,
                        f"{operation_name} completed in {duration:.3f}s",
                        extra=extra
                    )
                
                return result
                
            except Exception as e:
                duration = time.time() - start_time
                logger.error(
                    f"{operation_name} failed after {duration:.3f}s: {e}",
                    extra={'operation': operation_name, 'duration_seconds': duration, 'error': str(e)},
                    exc_info=True
                )
                raise
        
        @functools.wraps(func)
        async def async_wrapper(*args, **kwargs):
            nonlocal logger, operation_name
            
            if logger is None:
                logger = logging.getLogger(func.__module__)
            
            if operation_name is None:
                operation_name = func.__name__
            
            start_time = time.time()
            
            try:
                result = await func(*args, **kwargs)
                duration = time.time() - start_time
                
                # Log completion
                extra = {'operation': operation_name, 'duration_seconds': duration}
                
                if include_args and args:
                    extra['args_count'] = len(args)
                if include_args and kwargs:
                    extra['kwargs_keys'] = list(kwargs.keys())
                
                if duration > slow_threshold:
                    logger.warning(
                        f"{operation_name} completed slowly in {duration:.3f}s",
                        extra=extra
                    )
                else:
                    logger.log(
                        level,
                        f"{operation_name} completed in {duration:.3f}s",
                        extra=extra
                    )
                
                return result
                
            except Exception as e:
                duration = time.time() - start_time
                logger.error(
                    f"{operation_name} failed after {duration:.3f}s: {e}",
                    extra={'operation': operation_name, 'duration_seconds': duration, 'error': str(e)},
                    exc_info=True
                )
                raise
        
        # Return appropriate wrapper based on function type
        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        else:
            return sync_wrapper
    
    return decorator


# FIXED: Enhanced helper logging functions
def log_exception(
    logger: logging.Logger,
    message: str,
    exc_info: bool = True,
    extra: Optional[Dict[str, Any]] = None
) -> None:
    """
    Log exception with correlation and extra data
    
    Args:
        logger: Logger instance
        message: Log message
        exc_info: Include exception information
        extra: Extra data to include
    """
    log_extra = extra or {}
    
    # Add correlation if available
    correlation_id = correlation_context.get()
    if correlation_id:
        log_extra['correlation_id'] = correlation_id
    
    logger.error(message, exc_info=exc_info, extra=log_extra)


def log_audit_event(
    logger: logging.Logger,
    action: str,
    user_id: Optional[str] = None,
    resource_type: Optional[str] = None,
    resource_id: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None
) -> None:
    """
    Log audit event with structured data
    
    Args:
        logger: Logger instance
        action: Action performed
        user_id: User ID performing action
        resource_type: Type of resource affected
        resource_id: ID of resource affected
        details: Additional details
        ip_address: Client IP address
        user_agent: Client user agent
    """
    audit_data = {
        'event_type': 'audit',
        'action': action,
        'user_id': user_id,
        'resource_type': resource_type,
        'resource_id': resource_id,
        'details': details or {},
        'ip_address': ip_address,
        'user_agent': user_agent
    }
    
    # Add correlation if available
    correlation_id = correlation_context.get()
    if correlation_id:
        audit_data['correlation_id'] = correlation_id
    
    logger.info(f"Audit: {action}", extra=audit_data)


def log_performance(
    logger: logging.Logger,
    operation: str,
    duration: float,
    correlation_id: Optional[str] = None,
    **kwargs
) -> None:
    """
    Log performance metrics with correlation
    
    Args:
        logger: Logger instance
        operation: Operation name
        duration: Duration in seconds
        correlation_id: Correlation ID for the request
        **kwargs: Additional metrics
    """
    perf_data = {
        'event_type': 'performance',
        'operation': operation,
        'duration_seconds': duration,
        **kwargs
    }
    
    if correlation_id:
        perf_data['correlation_id'] = correlation_id
    elif correlation_context.get():
        perf_data['correlation_id'] = correlation_context.get()
    
    logger.info(f"Performance: {operation} took {duration:.3f}s", extra=perf_data)


def log_security_event(
    logger: logging.Logger,
    event_type: str,
    severity: str = "medium",
    user_id: Optional[str] = None,
    ip_address: Optional[str] = None,
    details: Optional[dict] = None,
    correlation_id: Optional[str] = None
) -> None:
    """
    Log security-related events with correlation
    
    Args:
        logger: Logger instance
        event_type: Type of security event
        severity: Event severity (low, medium, high, critical)
        user_id: User ID if applicable
        ip_address: Client IP address
        details: Additional details
        correlation_id: Correlation ID for the request
    """
    security_data = {
        'event_type': 'security',
        'security_event': event_type,
        'severity': severity,
        'user_id': user_id,
        'ip_address': ip_address,
        'details': details or {}
    }
    
    if correlation_id:
        security_data['correlation_id'] = correlation_id
    elif correlation_context.get():
        security_data['correlation_id'] = correlation_context.get()
    
    # Map severity to log level
    level_map = {
        'low': logging.INFO,
        'medium': logging.WARNING,
        'high': logging.ERROR,
        'critical': logging.CRITICAL
    }
    
    level = level_map.get(severity.lower(), logging.WARNING)
    logger.log(level, f"Security: {event_type}", extra=security_data)


# FIXED: Add missing import for asyncio
import asyncio

# Export commonly used functions and classes
__all__ = [
    'setup_logging',
    'get_logger',
    'JSONFormatter',
    'TextFormatter',
    'CorrelatedLogger',
    'CorrelatedTimedLogger',
    'LoggerMixin',
    'set_correlation_context',
    'clear_correlation_context',
    'get_correlation_context',
    'correlation_context_manager',
    'timed_operation',
    'log_exception',
    'log_audit_event',
    'log_performance',
    'log_security_event'
]