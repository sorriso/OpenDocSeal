"""
Path: infrastructure/source/api/routes/test_control.py
Version: 2
"""

import logging
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, status, Request
from pydantic import BaseModel

from ..dependencies import test_mode_only, get_test_hooks
from ..factories.service_factory import get_test_service_factory, TestHooks
from ..database import database, get_users_collection, get_documents_collection, get_audit_logs_collection
from ..config import get_settings
from ..models.base import ResponseModel

logger = logging.getLogger(__name__)
settings = get_settings()

router = APIRouter()


class TestStateResponse(BaseModel):
    """Test state information"""
    test_mode: bool
    services: Dict[str, Any]
    database_name: str
    bucket_name: str
    events_count: int
    correlation_enabled: bool
    environment: str
    test_hooks_active: bool


class ServiceControlRequest(BaseModel):
    """Service control request"""
    service: str  # blockchain, storage, auth
    action: str   # reset, configure, enable, disable, delay, error
    parameters: Optional[Dict[str, Any]] = None


class TestEventFilter(BaseModel):
    """Test event filter"""
    event_type: Optional[str] = None
    service: Optional[str] = None
    document_id: Optional[str] = None
    limit: int = 100
    since: Optional[datetime] = None


class MockConfiguration(BaseModel):
    """Mock service configuration"""
    service: str
    delay: Optional[float] = None
    success_rate: Optional[float] = None
    error_rate: Optional[float] = None
    responses: Optional[Dict[str, Any]] = None


@router.get(
    "/state",
    response_model=TestStateResponse,
    summary="Get test state",
    description="Get current test environment state and configuration",
)
async def get_test_state(
    test_hooks: Optional[TestHooks] = Depends(get_test_hooks)
) -> TestStateResponse:
    """Get current test environment state"""
    
    factory = get_test_service_factory()
    
    return TestStateResponse(
        test_mode=settings.test_mode,
        services=factory.get_service_info(),
        database_name=settings.effective_mongodb_db_name,
        bucket_name=settings.effective_minio_bucket_name,
        events_count=len(test_hooks.get_events()) if test_hooks else 0,
        correlation_enabled=settings.log_correlation,
        environment=settings.environment.value,
        test_hooks_active=test_hooks is not None
    )


@router.post(
    "/reset",
    response_model=ResponseModel,
    summary="Reset test environment",
    description="Reset all test services and optionally clear test data",
)
async def reset_test_environment(
    request: Request,
    clear_database: bool = False,
    clear_storage: bool = False,
    test_hooks: Optional[TestHooks] = Depends(get_test_hooks)
) -> ResponseModel:
    """Reset test environment to clean state"""
    
    try:
        factory = get_test_service_factory()
        reset_results = []
        
        # Reset service factory cache
        factory.reset_cache()
        reset_results.append("service_cache_reset")
        
        # Clear test hooks events
        if test_hooks:
            events_cleared = len(test_hooks.get_events())
            test_hooks.clear_events()
            reset_results.append(f"test_events_cleared: {events_cleared}")
        
        # Reset individual services
        try:
            # Reset blockchain service
            blockchain_service = factory.create_blockchain_service()
            if hasattr(blockchain_service, 'reset'):
                blockchain_service.reset()
                reset_results.append("blockchain_service_reset")
            
            # Reset storage service
            storage_service = factory.create_storage_service()
            if hasattr(storage_service, 'reset'):
                storage_service.reset()
                reset_results.append("storage_service_reset")
            
            # Reset auth service
            auth_service = factory.create_auth_service()
            if hasattr(auth_service, 'reset'):
                auth_service.reset()
                reset_results.append("auth_service_reset")
        
        except Exception as e:
            logger.warning(f"Error resetting some services: {e}")
            reset_results.append(f"service_reset_partial: {str(e)}")
        
        # Clear database collections if requested
        if clear_database:
            try:
                collections_cleared = []
                
                # Clear test users
                users_collection = get_users_collection()
                result = await users_collection.delete_many({
                    "$or": [
                        {"email": {"$regex": "test|mock", "$options": "i"}},
                        {"name": {"$regex": "test|mock", "$options": "i"}}
                    ]
                })
                if result.deleted_count > 0:
                    collections_cleared.append(f"test_users: {result.deleted_count}")
                
                # Clear test documents
                documents_collection = get_documents_collection()
                result = await documents_collection.delete_many({
                    "$or": [
                        {"name": {"$regex": "test|mock", "$options": "i"}},
                        {"description": {"$regex": "test|mock", "$options": "i"}}
                    ]
                })
                if result.deleted_count > 0:
                    collections_cleared.append(f"test_documents: {result.deleted_count}")
                
                # Clear recent audit logs (last hour only)
                one_hour_ago = datetime.now(timezone.utc) - datetime.timedelta(hours=1)
                audit_collection = get_audit_logs_collection()
                result = await audit_collection.delete_many({
                    "timestamp": {"$gte": one_hour_ago},
                    "$or": [
                        {"details.test": True},
                        {"user_id": {"$regex": "test", "$options": "i"}}
                    ]
                })
                if result.deleted_count > 0:
                    collections_cleared.append(f"test_audit_logs: {result.deleted_count}")
                
                if collections_cleared:
                    reset_results.extend(collections_cleared)
                else:
                    reset_results.append("no_test_data_found")
                    
            except Exception as e:
                logger.error(f"Database clear failed: {e}")
                reset_results.append(f"database_clear_error: {str(e)}")
        
        # Clear test storage if requested
        if clear_storage:
            try:
                storage_service = factory.create_storage_service()
                if hasattr(storage_service, 'clear_test_data'):
                    cleared_count = await storage_service.clear_test_data()
                    reset_results.append(f"storage_cleared: {cleared_count} objects")
                else:
                    reset_results.append("storage_clear_not_supported")
            except Exception as e:
                logger.error(f"Storage clear failed: {e}")
                reset_results.append(f"storage_clear_error: {str(e)}")
        
        correlation_id = getattr(request.state, 'correlation_id', None)
        logger.info(
            "Test environment reset completed",
            extra={
                "event_type": "test_reset",
                "correlation_id": correlation_id,
                "reset_results": reset_results
            }
        )
        
        return ResponseModel(
            success=True,
            message="Test environment reset successfully",
            data={
                "reset_timestamp": datetime.now(timezone.utc).isoformat(),
                "reset_results": reset_results,
                "correlation_id": correlation_id
            }
        )
        
    except Exception as e:
        logger.error(f"Failed to reset test environment: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Reset failed: {str(e)}"
        )


@router.post(
    "/services/control",
    response_model=ResponseModel,
    summary="Control test services",
    description="Control behavior of mock services for testing scenarios",
)
async def control_service(
    control_request: ServiceControlRequest,
    test_hooks: Optional[TestHooks] = Depends(get_test_hooks)
) -> ResponseModel:
    """Control mock service behavior"""
    
    try:
        factory = get_test_service_factory()
        result = {"service": control_request.service, "action": control_request.action}
        
        if control_request.service == "blockchain":
            blockchain_service = factory.create_blockchain_service()
            
            if control_request.action == "reset":
                if hasattr(blockchain_service, 'reset'):
                    blockchain_service.reset()
                    result["message"] = "Blockchain service reset successfully"
                else:
                    result["message"] = "Reset not supported for this service"
                    
            elif control_request.action == "delay" and control_request.parameters:
                delay = control_request.parameters.get("delay", 0.1)
                if hasattr(blockchain_service, 'set_delay'):
                    blockchain_service.set_delay(delay)
                    result["message"] = f"Delay set to {delay}s"
                else:
                    result["message"] = "Delay control not supported"
                    
            elif control_request.action == "error" and control_request.parameters:
                error_rate = control_request.parameters.get("error_rate", 0.1)
                if hasattr(blockchain_service, 'set_error_rate'):
                    blockchain_service.set_error_rate(error_rate)
                    result["message"] = f"Error rate set to {error_rate}"
                else:
                    result["message"] = "Error control not supported"
            
        elif control_request.service == "storage":
            storage_service = factory.create_storage_service()
            
            if control_request.action == "reset":
                if hasattr(storage_service, 'reset'):
                    storage_service.reset()
                    result["message"] = "Storage service reset successfully"
                else:
                    result["message"] = "Reset not supported for this service"
                    
            elif control_request.action == "delay" and control_request.parameters:
                delay = control_request.parameters.get("delay", 0.05)
                if hasattr(storage_service, 'set_delay'):
                    storage_service.set_delay(delay)
                    result["message"] = f"Delay set to {delay}s"
                else:
                    result["message"] = "Delay control not supported"
        
        elif control_request.service == "auth":
            auth_service = factory.create_auth_service()
            
            if control_request.action == "reset":
                if hasattr(auth_service, 'reset'):
                    auth_service.reset()
                    result["message"] = "Auth service reset successfully"
                else:
                    result["message"] = "Reset not supported for this service"
        
        else:
            result["message"] = f"Unknown service: {control_request.service}"
        
        logger.info(
            f"Service control executed: {control_request.service}.{control_request.action}",
            extra={
                "service": control_request.service,
                "action": control_request.action,
                "parameters": control_request.parameters,
                "result": result
            }
        )
        
        return ResponseModel(
            success=True,
            message="Service control executed",
            data=result
        )
        
    except Exception as e:
        logger.error(f"Service control failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Service control failed: {str(e)}"
        )


@router.get(
    "/events",
    response_model=List[Dict[str, Any]],
    summary="Get test events",
    description="Get filtered test events from test hooks",
)
async def get_test_events(
    event_filter: TestEventFilter = Depends(),
    test_hooks: Optional[TestHooks] = Depends(get_test_hooks)
) -> List[Dict[str, Any]]:
    """Get filtered test events"""
    
    if not test_hooks:
        return []
    
    try:
        events = test_hooks.get_events()
        
        # Apply filters
        if event_filter.event_type:
            events = [e for e in events if e.get("event_type") == event_filter.event_type]
        
        if event_filter.service:
            events = [e for e in events if e.get("service") == event_filter.service]
        
        if event_filter.document_id:
            events = [e for e in events if e.get("document_id") == event_filter.document_id]
        
        if event_filter.since:
            events = [e for e in events if e.get("timestamp") and 
                     datetime.fromisoformat(e["timestamp"]) >= event_filter.since]
        
        # Apply limit
        if event_filter.limit and len(events) > event_filter.limit:
            events = events[-event_filter.limit:]  # Get most recent events
        
        logger.debug(f"Retrieved {len(events)} test events with filters")
        
        return events
        
    except Exception as e:
        logger.error(f"Failed to get test events: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve test events"
        )


@router.post(
    "/events/clear",
    response_model=ResponseModel,
    summary="Clear test events",
    description="Clear all or filtered test events",
)
async def clear_test_events(
    event_type: Optional[str] = None,
    test_hooks: Optional[TestHooks] = Depends(get_test_hooks)
) -> ResponseModel:
    """Clear test events"""
    
    if not test_hooks:
        return ResponseModel(
            success=True,
            message="No test hooks available",
            data={"cleared_count": 0}
        )
    
    try:
        if event_type:
            # Clear specific event type
            events_before = len(test_hooks.get_events())
            # Note: This would require implementing filtered clear in TestHooks
            test_hooks.clear_events()  # For now, clear all
            events_after = 0
            cleared_count = events_before - events_after
        else:
            # Clear all events
            cleared_count = len(test_hooks.get_events())
            test_hooks.clear_events()
        
        logger.info(f"Cleared {cleared_count} test events")
        
        return ResponseModel(
            success=True,
            message=f"Cleared {cleared_count} test events",
            data={"cleared_count": cleared_count}
        )
        
    except Exception as e:
        logger.error(f"Failed to clear test events: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to clear test events"
        )


@router.get(
    "/database/info",
    response_model=Dict[str, Any],
    summary="Test database information",
    description="Get information about the test database",
)
async def get_test_database_info() -> Dict[str, Any]:
    """Get test database information"""
    
    try:
        db_health = await database.health_check()
        
        # Get collection counts
        collections_info = {}
        try:
            users_collection = get_users_collection()
            collections_info["users"] = await users_collection.count_documents({})
            
            documents_collection = get_documents_collection()
            collections_info["documents"] = await documents_collection.count_documents({})
            
            audit_collection = get_audit_logs_collection()
            collections_info["audit_logs"] = await audit_collection.count_documents({})
            
        except Exception as e:
            collections_info["error"] = str(e)
        
        return {
            "database_name": settings.effective_mongodb_db_name,
            "connection_status": db_health.get("status", "unknown"),
            "collections": collections_info,
            "database_stats": {
                "data_size": db_health.get("data_size", 0),
                "index_size": db_health.get("index_size", 0),
                "objects": db_health.get("objects", 0)
            }
        }
        
    except Exception as e:
        logger.error(f"Failed to get database info: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get database information"
        )


@router.get(
    "/correlation/{correlation_id}",
    response_model=Dict[str, Any],
    summary="Test correlation tracking",
    description="Test correlation ID functionality",
)
async def test_correlation(
    correlation_id: str,
    request: Request
) -> Dict[str, Any]:
    """Test correlation ID functionality"""
    
    actual_correlation = getattr(request.state, 'correlation_id', None)
    
    # Log test event with correlation
    logger.info(
        f"Correlation test requested: {correlation_id}",
        extra={
            "event_type": "correlation_test",
            "requested_id": correlation_id,
            "actual_id": actual_correlation,
            "correlation_id": actual_correlation
        }
    )
    
    return {
        "requested_correlation_id": correlation_id,
        "actual_correlation_id": actual_correlation,
        "match": correlation_id == actual_correlation,
        "headers": {
            "x_correlation_id": request.headers.get("X-Correlation-ID"),
            "x_request_id": request.headers.get("X-Request-ID")
        },
        "correlation_enabled": settings.log_correlation,
        "test_mode": settings.test_mode
    }


@router.get(
    "/health",
    response_model=Dict[str, Any],
    summary="Test environment health",
    description="Comprehensive health check for test environment",
)
async def test_environment_health() -> Dict[str, Any]:
    """Comprehensive health check for test environment"""
    
    try:
        factory = get_test_service_factory()
        health_results = {}
        
        # Check all services
        services = ["blockchain", "storage", "auth"]
        for service_name in services:
            try:
                if service_name == "blockchain":
                    service = factory.create_blockchain_service()
                    health = await service.health_check()
                    health_results[service_name] = {
                        "status": health.status,
                        "details": health.dict()
                    }
                elif service_name == "storage":
                    service = factory.create_storage_service()
                    health = await service.health_check()
                    health_results[service_name] = {
                        "status": health.get("status", "unknown"),
                        "details": health
                    }
                elif service_name == "auth":
                    # Auth service doesn't have health check, check basic functionality
                    service = factory.create_auth_service()
                    health_results[service_name] = {
                        "status": "healthy",
                        "details": {
                            "service_type": "mock" if hasattr(service, 'reset') else "production",
                            "test_mode": True
                        }
                    }
                    
            except Exception as e:
                health_results[service_name] = {
                    "status": "error",
                    "error": str(e)
                }
        
        # Check database
        try:
            db_health = await database.health_check()
            health_results["database"] = {
                "status": db_health.get("status", "unknown"),
                "details": db_health
            }
        except Exception as e:
            health_results["database"] = {
                "status": "error",
                "error": str(e)
            }
        
        # Overall status
        all_healthy = all(
            result.get("status") in ["healthy", "connected"]
            for result in health_results.values()
        )
        
        return {
            "overall_status": "healthy" if all_healthy else "degraded",
            "test_mode": settings.test_mode,
            "environment": settings.environment.value,
            "services": health_results,
            "configuration": {
                "database_name": settings.effective_mongodb_db_name,
                "bucket_name": settings.effective_minio_bucket_name,
                "correlation_enabled": settings.log_correlation
            },
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        
    except Exception as e:
        logger.error(f"Test environment health check failed: {e}")
        return {
            "overall_status": "error",
            "test_mode": settings.test_mode,
            "error": str(e),
            "timestamp": datetime.now(timezone.utc).isoformat()
        }


@router.post(
    "/configure",
    response_model=ResponseModel,
    summary="Configure mock services",
    description="Configure mock service behavior for testing",
)
async def configure_mock_services(
    configurations: List[MockConfiguration]
) -> ResponseModel:
    """Configure mock service behavior"""
    
    try:
        factory = get_test_service_factory()
        configuration_results = []
        
        for config in configurations:
            try:
                result = {"service": config.service, "configured": False}
                
                if config.service == "blockchain":
                    service = factory.create_blockchain_service()
                    if hasattr(service, 'configure'):
                        service.configure(
                            delay=config.delay,
                            success_rate=config.success_rate,
                            error_rate=config.error_rate,
                            responses=config.responses
                        )
                        result["configured"] = True
                
                elif config.service == "storage":
                    service = factory.create_storage_service()
                    if hasattr(service, 'configure'):
                        service.configure(
                            delay=config.delay,
                            error_rate=config.error_rate
                        )
                        result["configured"] = True
                
                elif config.service == "auth":
                    service = factory.create_auth_service()
                    if hasattr(service, 'configure'):
                        service.configure(
                            delay=config.delay,
                            responses=config.responses
                        )
                        result["configured"] = True
                
                configuration_results.append(result)
                
            except Exception as e:
                configuration_results.append({
                    "service": config.service,
                    "configured": False,
                    "error": str(e)
                })
        
        logger.info(
            "Mock services configured",
            extra={
                "configurations": configuration_results
            }
        )
        
        return ResponseModel(
            success=True,
            message="Mock services configured",
            data={"configurations": configuration_results}
        )
        
    except Exception as e:
        logger.error(f"Mock service configuration failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Configuration failed: {str(e)}"
        )