"""
Path: infrastructure/source/api/routes/health.py
Version: 3
"""

import logging
import asyncio
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import PlainTextResponse

from ..models.base import HealthCheckModel, ServiceHealthModel
from ..models.blockchain import BlockchainHealthStatus, TransactionStatistics
from ..services.interfaces import (
    BlockchainServiceInterface, StorageServiceInterface, AuthServiceInterface
)
from ..dependencies import (
    get_blockchain_service, get_storage_service, get_auth_service,
    get_admin_user, get_correlation_id, check_services_health
)
from ..database import database
from ..config import get_settings
from ..utils.rate_limiting import create_rate_limiter

logger = logging.getLogger(__name__)
settings = get_settings()

router = APIRouter()

# Application start time for uptime calculation
app_start_time = datetime.now(timezone.utc)


@router.get(
    "/",
    response_model=HealthCheckModel,
    summary="Basic health check",
    description="Basic application health status",
    responses={
        200: {"description": "Service is healthy"},
        503: {"description": "Service is unhealthy"}
    }
)
async def health_check(
    correlation_id: str = Depends(get_correlation_id)
) -> HealthCheckModel:
    """Basic health check endpoint"""
    
    try:
        # Calculate uptime
        uptime = (datetime.now(timezone.utc) - app_start_time).total_seconds()
        
        # Basic database connectivity check
        db_healthy = database.is_connected
        
        if not db_healthy:
            logger.error(
                "Database connection failed during health check",
                extra={"correlation_id": correlation_id}
            )
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Database connection failed"
            )
        
        logger.debug(
            "Health check successful",
            extra={
                "correlation_id": correlation_id,
                "uptime_seconds": uptime
            }
        )
        
        return HealthCheckModel(
            status="healthy",
            timestamp=datetime.now(timezone.utc),
            version=settings.app_version,
            uptime_seconds=uptime
        )
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(
            f"Health check failed: {e}",
            extra={"correlation_id": correlation_id}
        )
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Health check failed"
        )


@router.get(
    "/ping",
    response_class=PlainTextResponse,
    summary="Simple ping check",
    description="Simple ping response for load balancers",
    responses={
        200: {"description": "pong", "content": {"text/plain": {"example": "pong"}}}
    }
)
async def ping() -> str:
    """Simple ping endpoint"""
    return "pong"


@router.get(
    "/ready",
    response_model=Dict[str, Any],
    summary="Readiness check",
    description="Detailed readiness check for all services",
    responses={
        200: {"description": "Service is ready"},
        503: {"description": "Service is not ready"}
    }
)
async def readiness_check(
    correlation_id: str = Depends(get_correlation_id)
) -> Dict[str, Any]:
    """Comprehensive readiness check"""
    
    try:
        # Check all critical services
        services_health = await check_services_health()
        
        # Calculate overall health
        critical_services = ["database", "storage"]
        all_critical_healthy = all(
            services_health.get(service, "unknown") in ["healthy", "connected"]
            for service in critical_services
        )
        
        if not all_critical_healthy:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Critical services unhealthy"
            )
        
        # Calculate uptime
        uptime = (datetime.now(timezone.utc) - app_start_time).total_seconds()
        
        result = {
            "status": "ready",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "uptime_seconds": uptime,
            "version": settings.app_version,
            "environment": settings.environment,
            "services": services_health,
            "configuration": {
                "test_mode": settings.test_mode,
                "debug": settings.debug,
                "blockchain_mode": settings.blockchain_mode,
                "storage_mode": settings.storage_mode
            }
        }
        
        logger.info(
            "Readiness check successful",
            extra={
                "correlation_id": correlation_id,
                "services_status": services_health
            }
        )
        
        return result
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(
            f"Readiness check failed: {e}",
            extra={"correlation_id": correlation_id}
        )
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Readiness check failed"
        )


@router.get(
    "/live",
    response_model=Dict[str, Any],
    summary="Liveness check",
    description="Liveness check for container orchestration",
    responses={
        200: {"description": "Service is alive"},
        503: {"description": "Service is not alive"}
    }
)
async def liveness_check(
    correlation_id: str = Depends(get_correlation_id)
) -> Dict[str, Any]:
    """Liveness check for container orchestration"""
    
    try:
        # Basic liveness indicators
        uptime = (datetime.now(timezone.utc) - app_start_time).total_seconds()
        
        # Check if we can access basic system resources
        import psutil
        cpu_usage = psutil.cpu_percent(interval=0.1)
        memory_info = psutil.virtual_memory()
        
        # Basic thresholds for liveness
        if memory_info.percent > 95:  # Memory usage > 95%
            logger.warning("High memory usage detected", extra={"memory_percent": memory_info.percent})
        
        result = {
            "status": "alive",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "uptime_seconds": uptime,
            "process": {
                "cpu_percent": cpu_usage,
                "memory_percent": memory_info.percent,
                "memory_available": memory_info.available
            }
        }
        
        return result
        
    except Exception as e:
        logger.error(
            f"Liveness check failed: {e}",
            extra={"correlation_id": correlation_id}
        )
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Liveness check failed"
        )


@router.get(
    "/detailed",
    response_model=Dict[str, Any],
    summary="Detailed health check",
    description="Comprehensive health check with all service details",
    responses={
        200: {"description": "Detailed health information"},
        401: {"description": "Authentication required"},
        503: {"description": "Some services are unhealthy"}
    }
)
async def detailed_health_check(
    current_user=Depends(get_admin_user),
    blockchain_service: BlockchainServiceInterface = Depends(get_blockchain_service),
    storage_service: StorageServiceInterface = Depends(get_storage_service),
    auth_service: AuthServiceInterface = Depends(get_auth_service),
    correlation_id: str = Depends(get_correlation_id)
) -> Dict[str, Any]:
    """Comprehensive health check with detailed service information"""
    
    try:
        # Gather detailed health information from all services
        health_checks = {}
        
        # Database health
        try:
            db_health = await database.health_check()
            health_checks["database"] = ServiceHealthModel(
                name="MongoDB",
                status=db_health.get("status", "unknown"),
                response_time=db_health.get("response_time_seconds"),
                details=db_health
            )
        except Exception as e:
            health_checks["database"] = ServiceHealthModel(
                name="MongoDB",
                status="error",
                error=str(e)
            )
        
        # Blockchain service health
        try:
            blockchain_health = await blockchain_service.health_check()
            health_checks["blockchain"] = ServiceHealthModel(
                name="Blockchain",
                status=blockchain_health.status,
                details={
                    "network": blockchain_health.network,
                    "mode": blockchain_health.mode,
                    "pending_transactions": blockchain_health.pending_transactions,
                    "last_block_time": blockchain_health.last_block_time,
                    "connection_status": blockchain_health.connection_status
                }
            )
        except Exception as e:
            health_checks["blockchain"] = ServiceHealthModel(
                name="Blockchain",
                status="error",
                error=str(e)
            )
        
        # Storage service health
        try:
            storage_health = await storage_service.health_check()
            health_checks["storage"] = ServiceHealthModel(
                name="MinIO",
                status=storage_health.get("status", "unknown"),
                details=storage_health
            )
        except Exception as e:
            health_checks["storage"] = ServiceHealthModel(
                name="MinIO",
                status="error",
                error=str(e)
            )
        
        # Auth service health (basic check)
        try:
            # Auth service doesn't have a health check method, so we'll do a basic check
            health_checks["auth"] = ServiceHealthModel(
                name="Authentication",
                status="healthy",
                details={
                    "service_type": "active",
                    "sso_enabled": settings.enable_sso
                }
            )
        except Exception as e:
            health_checks["auth"] = ServiceHealthModel(
                name="Authentication", 
                status="error",
                error=str(e)
            )
        
        # Rate limiter health
        try:
            rate_limiter = create_rate_limiter()
            limiter_stats = rate_limiter.get_statistics()
            health_checks["rate_limiter"] = ServiceHealthModel(
                name="Rate Limiter",
                status="healthy",
                details=limiter_stats
            )
        except Exception as e:
            health_checks["rate_limiter"] = ServiceHealthModel(
                name="Rate Limiter",
                status="error",
                error=str(e)
            )
        
        # System resources
        try:
            import psutil
            disk_usage = psutil.disk_usage('/')
            health_checks["system"] = ServiceHealthModel(
                name="System Resources",
                status="healthy",
                details={
                    "cpu_percent": psutil.cpu_percent(interval=0.1),
                    "memory": {
                        "total": psutil.virtual_memory().total,
                        "available": psutil.virtual_memory().available,
                        "percent": psutil.virtual_memory().percent
                    },
                    "disk": {
                        "total": disk_usage.total,
                        "free": disk_usage.free,
                        "percent": (disk_usage.used / disk_usage.total) * 100
                    }
                }
            )
        except Exception as e:
            health_checks["system"] = ServiceHealthModel(
                name="System Resources",
                status="error", 
                error=str(e)
            )
        
        # Calculate overall status
        error_services = [name for name, check in health_checks.items() if check.status == "error"]
        overall_status = "healthy" if not error_services else "degraded"
        
        if len(error_services) > len(health_checks) // 2:
            overall_status = "critical"
        
        # Calculate uptime
        uptime = (datetime.now(timezone.utc) - app_start_time).total_seconds()
        
        result = {
            "status": overall_status,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "version": settings.app_version,
            "environment": settings.environment,
            "uptime_seconds": uptime,
            "services": {name: check.dict() for name, check in health_checks.items()},
            "error_services": error_services,
            "configuration": {
                "test_mode": settings.test_mode,
                "debug": settings.debug,
                "blockchain_network": settings.blockchain_network,
                "blockchain_mode": settings.blockchain_mode,
                "storage_mode": settings.storage_mode,
                "rate_limiting": settings.rate_limit_enabled
            }
        }
        
        # Set appropriate status code
        if overall_status in ["degraded", "critical"]:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail=result
            )
        
        logger.info(
            f"Detailed health check completed: {overall_status}",
            extra={
                "correlation_id": correlation_id,
                "overall_status": overall_status,
                "error_services": error_services
            }
        )
        
        return result
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(
            f"Detailed health check failed: {e}",
            extra={"correlation_id": correlation_id}
        )
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Detailed health check failed"
        )


@router.get(
    "/metrics",
    response_model=Dict[str, Any],
    summary="Health metrics",
    description="Application and service metrics for monitoring",
    responses={
        200: {"description": "Health metrics retrieved"},
        401: {"description": "Authentication required"}
    }
)
async def health_metrics(
    current_user=Depends(get_admin_user),
    correlation_id: str = Depends(get_correlation_id)
) -> Dict[str, Any]:
    """Get application and service metrics"""
    
    try:
        # Calculate uptime
        uptime = (datetime.now(timezone.utc) - app_start_time).total_seconds()
        
        # Database metrics
        db_metrics = {}
        try:
            db_health = await database.health_check()
            db_metrics = {
                "response_time": db_health.get("response_time_seconds", 0),
                "collections": db_health.get("collections", 0),
                "data_size": db_health.get("data_size", 0),
                "objects": db_health.get("objects", 0)
            }
        except Exception:
            db_metrics = {"error": "Unable to retrieve database metrics"}
        
        # Rate limiter metrics
        rate_limiter_metrics = {}
        try:
            rate_limiter = create_rate_limiter()
            rate_limiter_metrics = rate_limiter.get_statistics()
        except Exception:
            rate_limiter_metrics = {"error": "Unable to retrieve rate limiter metrics"}
        
        # System metrics
        system_metrics = {}
        try:
            import psutil
            system_metrics = {
                "cpu_percent": psutil.cpu_percent(interval=0.1),
                "memory_percent": psutil.virtual_memory().percent,
                "disk_percent": psutil.disk_usage('/').used / psutil.disk_usage('/').total * 100,
                "load_average": psutil.getloadavg() if hasattr(psutil, 'getloadavg') else None
            }
        except Exception:
            system_metrics = {"error": "Unable to retrieve system metrics"}
        
        metrics = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "uptime_seconds": uptime,
            "application": {
                "version": settings.app_version,
                "environment": settings.environment,
                "test_mode": settings.test_mode,
                "start_time": app_start_time.isoformat()
            },
            "database": db_metrics,
            "rate_limiter": rate_limiter_metrics,
            "system": system_metrics
        }
        
        logger.info(
            "Health metrics retrieved",
            extra={"correlation_id": correlation_id}
        )
        
        return metrics
        
    except Exception as e:
        logger.error(
            f"Failed to retrieve health metrics: {e}",
            extra={"correlation_id": correlation_id}
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve metrics"
        )


@router.get(
    "/blockchain",
    response_model=BlockchainHealthStatus,
    summary="Blockchain service health",
    description="Detailed blockchain service health and statistics",
    responses={
        200: {"description": "Blockchain health retrieved"},
        401: {"description": "Authentication required"},
        503: {"description": "Blockchain service unhealthy"}
    }
)
async def blockchain_health(
    current_user=Depends(get_admin_user),
    blockchain_service: BlockchainServiceInterface = Depends(get_blockchain_service),
    correlation_id: str = Depends(get_correlation_id)
) -> BlockchainHealthStatus:
    """Get detailed blockchain service health"""
    
    try:
        health_status = await blockchain_service.health_check()
        
        if health_status.status != "healthy":
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail=health_status.dict()
            )
        
        logger.info(
            f"Blockchain health check: {health_status.status}",
            extra={
                "correlation_id": correlation_id,
                "blockchain_status": health_status.status,
                "network": health_status.network
            }
        )
        
        return health_status
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(
            f"Blockchain health check failed: {e}",
            extra={"correlation_id": correlation_id}
        )
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Blockchain service health check failed"
        )


@router.post(
    "/restart",
    response_model=Dict[str, Any],
    summary="Restart services",
    description="Restart or reset specific services (admin only)",
    responses={
        200: {"description": "Services restarted successfully"},
        401: {"description": "Authentication required"},
        403: {"description": "Admin access required"}
    }
)
async def restart_services(
    services: List[str],
    current_user=Depends(get_admin_user),
    correlation_id: str = Depends(get_correlation_id)
) -> Dict[str, Any]:
    """Restart or reset specific services (admin only)"""
    
    try:
        restart_results = {}
        
        for service_name in services:
            try:
                if service_name == "rate_limiter":
                    # Reset rate limiter statistics
                    rate_limiter = create_rate_limiter()
                    await rate_limiter.reset_statistics()
                    restart_results[service_name] = "reset_successful"
                    
                elif service_name == "database":
                    # Reconnect database
                    await database.disconnect()
                    await database.connect()
                    restart_results[service_name] = "reconnected"
                    
                else:
                    restart_results[service_name] = "unsupported"
                    
            except Exception as e:
                restart_results[service_name] = f"error: {str(e)}"
        
        logger.warning(
            f"Services restart requested by admin",
            extra={
                "correlation_id": correlation_id,
                "admin_user_id": str(current_user.id),
                "services": services,
                "results": restart_results
            }
        )
        
        return {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "requested_services": services,
            "results": restart_results
        }
        
    except Exception as e:
        logger.error(
            f"Services restart failed: {e}",
            extra={"correlation_id": correlation_id}
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Services restart failed"
        )