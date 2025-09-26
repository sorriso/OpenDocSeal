"""
Path: infrastructure/source/api/database.py
Version: 5 - PERFORMANCE OPTIMIZATIONS
"""

import logging
from typing import Optional, Dict, Any, List, Tuple, Union
from datetime import datetime, timezone, timedelta
import asyncio
import uuid

from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorDatabase, AsyncIOMotorCollection
# FIXED: Updated error imports for PyMongo 4.15.1+ compatibility
from pymongo.errors import (
    ConnectionFailure, 
    ServerSelectionTimeoutError, 
    DuplicateKeyError,
    NetworkTimeout,
    ExecutionTimeout,
    WriteConcernError,
    WriteError,
    BulkWriteError,
    ConfigurationError,
    InvalidOperation,
    OperationFailure
)
from pymongo import IndexModel, ASCENDING, DESCENDING, TEXT
from pymongo.write_concern import WriteConcern
from pymongo.read_concern import ReadConcern
from pymongo.read_preferences import ReadPreference
from bson import ObjectId
from bson.errors import InvalidId

from .config import get_settings
from .models.base import AuditAction, UserRole

logger = logging.getLogger(__name__)
settings = get_settings()


class Database:
    """MongoDB database connection manager with Motor 3.7.1+ support and performance optimizations"""
    
    def __init__(self):
        self.client: Optional[AsyncIOMotorClient] = None
        self.database: Optional[AsyncIOMotorDatabase] = None
        self._is_connected: bool = False
        self._connection_info: Dict[str, Any] = {}
    
    @property
    def is_connected(self) -> bool:
        """Check if database is connected"""
        return self._is_connected and self.client is not None
    
    @property
    def connection_info(self) -> Dict[str, Any]:
        """Get connection information"""
        return self._connection_info.copy()
    
    async def connect(self) -> None:
        """Connect to MongoDB database with enhanced error handling and optimized settings"""
        try:
            db_name = settings.effective_mongodb_db_name
            logger.info(f"Connecting to MongoDB database: {db_name}")
            
            # OPTIMIZED: Enhanced connection parameters for better performance
            connection_params = {
                # Connection pool optimization
                "maxPoolSize": min(settings.mongodb_max_connections, 200),  # Cap at 200 for performance
                "minPoolSize": max(settings.mongodb_min_connections, 5),    # Minimum 5 for availability
                "maxIdleTimeMS": 300000,  # 5 minutes - close idle connections
                "waitQueueTimeoutMS": 10000,  # 10 seconds max wait for connection
                
                # Timeout optimization for better responsiveness
                "connectTimeoutMS": min(settings.mongodb_connect_timeout_ms, 15000),  # Max 15s
                "serverSelectionTimeoutMS": min(settings.mongodb_server_selection_timeout_ms, 20000),  # Max 20s
                "socketTimeoutMS": settings.mongodb_socket_timeout_ms or 30000,  # 30s default
                "heartbeatFrequencyMS": max(settings.mongodb_heartbeat_frequency_ms, 10000),  # Min 10s
                
                # Performance optimization
                "retryWrites": True,
                "retryReads": True,
                "readPreference": ReadPreference.PRIMARY_PREFERRED,  # Better performance than PRIMARY
                "compressors": ["snappy", "zlib"],  # Enable compression
                
                # Connection efficiency
                "maxConnecting": 10,  # Limit concurrent connections
                "loadBalanced": False,  # Disable for single server
                
                # Write concern for better performance/durability balance
                "w": "majority",
                "wtimeoutMS": 10000,  # 10 second write timeout
                "journal": True  # Ensure durability
            }
            
            logger.debug(f"MongoDB connection parameters: {self._mask_connection_params(connection_params)}")
            
            # Create client with optimized parameters
            self.client = AsyncIOMotorClient(
                settings.mongodb_url,
                **connection_params
            )
            
            # OPTIMIZED: Enhanced connection test with proper timeout handling
            try:
                # Test connection with shorter timeout for faster failure detection
                await asyncio.wait_for(
                    self.client.admin.command('ping'), 
                    timeout=5.0  # Reduced from settings timeout for faster detection
                )
                
                # Get server info for connection verification
                server_info = await self.client.server_info()
                
                self._connection_info = {
                    "server_version": server_info.get("version", "unknown"),
                    "database_name": db_name,
                    "max_pool_size": connection_params.get("maxPoolSize", 100),
                    "min_pool_size": connection_params.get("minPoolSize", 10),
                    "connection_timeout_ms": connection_params.get("connectTimeoutMS", 20000),
                    "server_selection_timeout_ms": connection_params.get("serverSelectionTimeoutMS", 30000),
                    "optimizations_enabled": True  # Flag for monitoring
                }
                
                logger.info(f"MongoDB server version: {server_info.get('version', 'unknown')}")
                
            except asyncio.TimeoutError:
                raise ConnectionFailure("MongoDB connection timeout during ping test")
            except Exception as e:
                raise ConnectionFailure(f"MongoDB ping test failed: {e}")
            
            # Get database with optimized read/write concerns
            self.database = self.client[db_name]
            
            # OPTIMIZED: Configure database with performance-oriented concerns
            write_concern = WriteConcern(
                w="majority",
                wtimeout=10000,  # 10 second timeout
                j=True  # Journal for durability
            )
            
            read_concern = ReadConcern(level="majority")  # Ensure consistency
            
            self.database = self.database.with_options(
                write_concern=write_concern,
                read_concern=read_concern,
                read_preference=ReadPreference.PRIMARY_PREFERRED  # Better performance
            )
            
            # Initialize collections and indexes with optimizations
            await self._initialize_collections_optimized()
            
            self._is_connected = True
            logger.info(f"Successfully connected to MongoDB database: {db_name} (optimized)")
            
        except (ConnectionFailure, ServerSelectionTimeoutError, NetworkTimeout) as e:
            logger.error(f"Failed to connect to MongoDB: {e}")
            self._is_connected = False
            await self._cleanup_failed_connection()
            raise
        except Exception as e:
            logger.error(f"Unexpected error connecting to MongoDB: {e}")
            self._is_connected = False
            await self._cleanup_failed_connection()
            raise
    
    async def disconnect(self) -> None:
        """Disconnect from MongoDB with proper cleanup"""
        try:
            if self.client:
                logger.info("Disconnecting from MongoDB...")
                
                # OPTIMIZED: Graceful shutdown with timeout
                try:
                    await asyncio.wait_for(
                        self.client.close(),
                        timeout=5.0  # Max 5 seconds for cleanup
                    )
                except asyncio.TimeoutError:
                    logger.warning("MongoDB disconnect timeout, forcing close")
                    
                self.client = None
                self.database = None
                self._is_connected = False
                self._connection_info.clear()
                
                logger.info("Successfully disconnected from MongoDB")
                
        except Exception as e:
            logger.error(f"Error disconnecting from MongoDB: {e}")
    
    async def health_check(self) -> Dict[str, Any]:
        """Perform database health check with performance metrics"""
        if not self.is_connected:
            return {
                "status": "disconnected",
                "error": "Database not connected"
            }
        
        try:
            start_time = asyncio.get_event_loop().time()
            
            # OPTIMIZED: Parallel health checks for better performance
            health_tasks = [
                self.client.admin.command('ping'),
                self.database.command("dbStats"),
                self.database.command("serverStatus")
            ]
            
            try:
                # Execute health checks in parallel with timeout
                ping_result, db_stats, server_status = await asyncio.wait_for(
                    asyncio.gather(*health_tasks, return_exceptions=True),
                    timeout=10.0
                )
                
                response_time = asyncio.get_event_loop().time() - start_time
                
            except asyncio.TimeoutError:
                return {
                    "status": "timeout",
                    "error": "Health check timeout after 10 seconds"
                }
            
            # Process results
            stats = db_stats if not isinstance(db_stats, Exception) else {}
            server_info = server_status if not isinstance(server_status, Exception) else {}
            
            # OPTIMIZED: Enhanced health information with performance metrics
            health_info = {
                "status": "healthy",
                "database_name": self.database.name,
                "response_time_seconds": round(response_time, 3),
                "collections": stats.get("collections", 0),
                "data_size_mb": round(stats.get("dataSize", 0) / 1024 / 1024, 2),
                "index_size_mb": round(stats.get("indexSize", 0) / 1024 / 1024, 2),
                "objects": stats.get("objects", 0),
                "connection_info": self._connection_info,
                
                # Performance metrics
                "performance": {
                    "avg_obj_size": stats.get("avgObjSize", 0),
                    "storage_size_mb": round(stats.get("storageSize", 0) / 1024 / 1024, 2),
                    "index_efficiency": round(stats.get("indexSize", 1) / max(stats.get("dataSize", 1), 1), 3),
                    "fragmentation_ratio": round(stats.get("storageSize", 1) / max(stats.get("dataSize", 1), 1), 2)
                },
                
                # Connection pool status
                "connections": {
                    "current": server_info.get("connections", {}).get("current", 0),
                    "available": server_info.get("connections", {}).get("available", 0),
                    "total_created": server_info.get("connections", {}).get("totalCreated", 0)
                }
            }
            
            return health_info
            
        except Exception as e:
            logger.error(f"Database health check failed: {e}")
            return {
                "status": "unhealthy",
                "error": str(e),
                "error_type": type(e).__name__
            }
    
    async def _initialize_collections_optimized(self) -> None:
        """Initialize database collections and indexes with performance optimizations"""
        try:
            # OPTIMIZED: Enhanced collections configuration for better performance
            collections_config = {
                "users": [
                    # Primary indexes
                    IndexModel([("email", ASCENDING)], unique=True, background=True, name="email_unique"),
                    IndexModel([("sso_id", ASCENDING)], sparse=True, background=True, name="sso_id_sparse"),
                    
                    # Query optimization indexes
                    IndexModel([("role", ASCENDING), ("is_active", ASCENDING)], background=True, name="role_active"),
                    IndexModel([("is_active", ASCENDING), ("created_at", DESCENDING)], background=True, name="active_created"),
                    IndexModel([("last_login", DESCENDING)], sparse=True, background=True, name="last_login_desc"),
                    
                    # Search index
                    IndexModel([("email", TEXT), ("name", TEXT)], background=True, name="user_text_search"),
                    
                    # Compound indexes for common queries
                    IndexModel([("organization", ASCENDING), ("role", ASCENDING)], sparse=True, background=True, name="org_role"),
                ],
                
                "documents": [
                    # Primary indexes
                    IndexModel([("user_id", ASCENDING), ("created_at", DESCENDING)], background=True, name="user_created"),
                    IndexModel([("hash", ASCENDING)], unique=True, background=True, name="hash_unique"),
                    IndexModel([("reference", ASCENDING)], unique=True, background=True, name="reference_unique"),
                    
                    # Query optimization indexes
                    IndexModel([("status", ASCENDING), ("created_at", DESCENDING)], background=True, name="status_created"),
                    IndexModel([("user_id", ASCENDING), ("status", ASCENDING)], background=True, name="user_status"),
                    IndexModel([("file_type", ASCENDING)], background=True, name="file_type"),
                    
                    # Search and filtering indexes
                    IndexModel([("name", TEXT), ("metadata", TEXT)], background=True, name="document_text_search"),
                    IndexModel([("created_at", DESCENDING)], background=True, name="created_desc"),
                    IndexModel([("updated_at", DESCENDING)], background=True, name="updated_desc"),
                    
                    # Compound indexes for complex queries
                    IndexModel([("user_id", ASCENDING), ("file_type", ASCENDING), ("created_at", DESCENDING)], background=True, name="user_type_created"),
                ],
                
                "blockchain_transactions": [
                    IndexModel([("document_hash", ASCENDING)], background=True, name="doc_hash"),
                    IndexModel([("transaction_id", ASCENDING)], sparse=True, background=True, name="tx_id"),
                    IndexModel([("status", ASCENDING), ("created_at", DESCENDING)], background=True, name="status_created"),
                    IndexModel([("created_at", DESCENDING)], background=True, name="created_desc"),
                    
                    # Cleanup index for old transactions
                    IndexModel([("created_at", ASCENDING)], background=True, expireAfterSeconds=365*24*3600, name="ttl_cleanup"),
                ],
                
                "audit_logs": [
                    IndexModel([("user_id", ASCENDING), ("timestamp", DESCENDING)], background=True, name="user_timestamp"),
                    IndexModel([("action", ASCENDING), ("timestamp", DESCENDING)], background=True, name="action_timestamp"),
                    IndexModel([("ip_address", ASCENDING)], background=True, name="ip_address"),
                    IndexModel([("correlation_id", ASCENDING)], sparse=True, background=True, name="correlation_id"),
                    
                    # TTL index - auto-delete after 90 days for performance
                    IndexModel([("timestamp", ASCENDING)], background=True, expireAfterSeconds=90*24*3600, name="audit_ttl"),
                ],
                
                "api_keys": [
                    IndexModel([("user_id", ASCENDING)], background=True, name="user_id"),
                    IndexModel([("key_hash", ASCENDING)], unique=True, background=True, name="key_hash_unique"),
                    IndexModel([("is_active", ASCENDING)], background=True, name="is_active"),
                    IndexModel([("expires_at", ASCENDING)], sparse=True, background=True, name="expires_at"),
                    
                    # TTL index for expired keys
                    IndexModel([("expires_at", ASCENDING)], background=True, expireAfterSeconds=0, name="api_key_ttl"),
                ],
                
                "user_sessions": [
                    IndexModel([("user_id", ASCENDING)], background=True, name="user_id"),
                    IndexModel([("session_token", ASCENDING)], unique=True, background=True, name="session_token_unique"),
                    
                    # TTL index - auto-delete after 7 days
                    IndexModel([("created_at", ASCENDING)], background=True, expireAfterSeconds=7*24*3600, name="session_ttl"),
                ]
            }
            
            # OPTIMIZED: Create indexes in parallel for faster initialization
            initialization_tasks = []
            
            for collection_name, indexes in collections_config.items():
                task = self._initialize_collection_with_indexes(collection_name, indexes)
                initialization_tasks.append(task)
            
            # Execute collection initialization in parallel
            await asyncio.gather(*initialization_tasks, return_exceptions=True)
            
            logger.info("Database collections and indexes initialized successfully (optimized)")
            
        except Exception as e:
            logger.error(f"Failed to initialize database collections: {e}")
            raise
    
    async def _initialize_collection_with_indexes(self, collection_name: str, indexes: List[IndexModel]) -> None:
        """Initialize single collection with indexes (helper for parallel execution)"""
        try:
            collection = self.database[collection_name]
            
            # OPTIMIZED: Check existing indexes to avoid unnecessary operations
            existing_indexes = {idx["name"] for idx in await collection.list_indexes().to_list(None)}
            
            # Filter out indexes that already exist
            indexes_to_create = []
            for idx in indexes:
                idx_name = getattr(idx, 'document', {}).get('name') or idx.document.get('name')
                if idx_name and idx_name not in existing_indexes:
                    indexes_to_create.append(idx)
            
            if indexes_to_create:
                # Create indexes in background for better performance
                result = await collection.create_indexes(indexes_to_create)
                logger.debug(f"Created {len(result)} new indexes for collection {collection_name}")
            else:
                logger.debug(f"All indexes already exist for collection {collection_name}")
                
        except Exception as e:
            logger.error(f"Failed to initialize collection {collection_name}: {e}")
            # Don't raise - continue with other collections
    
    async def _cleanup_failed_connection(self) -> None:
        """Cleanup after failed connection attempt"""
        try:
            if self.client:
                self.client.close()
                await asyncio.sleep(0.1)  # Give time for cleanup
        except Exception as e:
            logger.debug(f"Error during connection cleanup: {e}")
        finally:
            self.client = None
            self.database = None
            self._connection_info.clear()
    
    def _mask_connection_params(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Mask sensitive information in connection parameters for logging"""
        masked = params.copy()
        # Remove or mask any sensitive data if present
        return {k: v for k, v in masked.items() if not k.lower().endswith('password')}


# Global database instance
database = Database()


# Connection management functions
async def connect_to_mongo() -> None:
    """Connect to MongoDB database"""
    await database.connect()


async def close_mongo_connection() -> None:
    """Close MongoDB connection"""
    await database.disconnect()


# Collection accessor functions
def get_users_collection() -> AsyncIOMotorCollection:
    """Get users collection"""
    if not database.is_connected:
        raise RuntimeError("Database not connected")
    return database.database["users"]


def get_documents_collection() -> AsyncIOMotorCollection:
    """Get documents collection"""
    if not database.is_connected:
        raise RuntimeError("Database not connected")
    return database.database["documents"]


def get_blockchain_transactions_collection() -> AsyncIOMotorCollection:
    """Get blockchain transactions collection"""
    if not database.is_connected:
        raise RuntimeError("Database not connected")
    return database.database["blockchain_transactions"]


def get_audit_logs_collection() -> AsyncIOMotorCollection:
    """Get audit logs collection"""
    if not database.is_connected:
        raise RuntimeError("Database not connected")
    return database.database["audit_logs"]


def get_api_keys_collection() -> AsyncIOMotorCollection:
    """Get API keys collection"""
    if not database.is_connected:
        raise RuntimeError("Database not connected")
    return database.database["api_keys"]


def get_user_sessions_collection() -> AsyncIOMotorCollection:
    """Get user sessions collection"""
    if not database.is_connected:
        raise RuntimeError("Database not connected")
    return database.database["user_sessions"]


# OPTIMIZED: High-performance pagination function
async def paginate_query_optimized(
    collection: AsyncIOMotorCollection,
    query: Dict[str, Any],
    page: int = 1,
    page_size: int = 20,
    sort_by: Optional[str] = None,
    sort_order: int = DESCENDING,
    use_cursor: bool = True,
    last_id: Optional[str] = None
) -> Tuple[List[Dict[str, Any]], int, Optional[str]]:
    """
    OPTIMIZED pagination using cursor-based approach for better performance
    
    Args:
        collection: MongoDB collection
        query: Query filter
        page: Page number (1-based) - ignored if using cursor
        page_size: Items per page
        sort_by: Field to sort by
        sort_order: Sort order (ASCENDING or DESCENDING)
        use_cursor: Use cursor-based pagination (much faster for large datasets)
        last_id: Last document ID for cursor pagination
    
    Returns:
        Tuple of (items, total_count, next_cursor)
    """
    try:
        # Validate and sanitize parameters
        if page < 1:
            page = 1
        if page_size < 1 or page_size > 1000:  # Limit max page size
            page_size = min(max(page_size, 1), 1000)
        
        sort_field = sort_by or "_id"
        
        if use_cursor and last_id and sort_field == "_id":
            # OPTIMIZED: Cursor-based pagination - much faster for large collections
            cursor_query = query.copy()
            
            # Add cursor condition
            try:
                cursor_id = ObjectId(last_id)
                if sort_order == DESCENDING:
                    cursor_query["_id"] = {"$lt": cursor_id}
                else:
                    cursor_query["_id"] = {"$gt": cursor_id}
            except InvalidId:
                # Invalid cursor, fall back to first page
                pass
            
            # Get items with cursor
            cursor = collection.find(cursor_query).sort(sort_field, sort_order).limit(page_size + 1)
            items = await cursor.to_list(page_size + 1)
            
            # Determine if there's a next page and get next cursor
            has_more = len(items) > page_size
            if has_more:
                items = items[:-1]  # Remove the extra item
                next_cursor = str(items[-1]["_id"]) if items else None
            else:
                next_cursor = None
            
            # Get total count using optimized approach
            if page == 1 and not last_id:  # Only calculate total on first request
                total_count = await collection.count_documents(query)
            else:
                total_count = -1  # Indicate unknown for cursor pagination
            
        else:
            # OPTIMIZED: Use aggregation pipeline for better performance
            pipeline = [
                {"$match": query},
                {
                    "$facet": {
                        "data": [
                            {"$sort": {sort_field: sort_order}},
                            {"$skip": (page - 1) * page_size},
                            {"$limit": page_size}
                        ],
                        "total": [
                            {"$count": "count"}
                        ]
                    }
                }
            ]
            
            # Execute aggregation with timeout
            cursor = collection.aggregate(pipeline)
            result = await asyncio.wait_for(cursor.to_list(1), timeout=30.0)
            
            if not result:
                return [], 0, None
            
            items = result[0]["data"]
            total_count = result[0]["total"][0]["count"] if result[0]["total"] else 0
            next_cursor = str(items[-1]["_id"]) if items and use_cursor else None
        
        return items, total_count, next_cursor
        
    except asyncio.TimeoutError:
        logger.error("Pagination query timeout")
        raise
    except Exception as e:
        logger.error(f"Pagination query failed: {e}")
        raise


# Legacy pagination function for compatibility
async def paginate_query(
    collection: AsyncIOMotorCollection,
    query: Dict[str, Any],
    page: int = 1,
    page_size: int = 20,
    sort_by: Optional[str] = None,
    sort_order: int = DESCENDING,
    use_aggregation: bool = True
) -> Tuple[List[Dict[str, Any]], int]:
    """
    Legacy pagination function - automatically uses optimized version
    
    Returns:
        Tuple of (items, total_count)
    """
    items, total_count, _ = await paginate_query_optimized(
        collection=collection,
        query=query,
        page=page,
        page_size=page_size,
        sort_by=sort_by,
        sort_order=sort_order,
        use_cursor=False,  # Disable cursor for legacy compatibility
        last_id=None
    )
    
    return items, total_count


# Utility functions (keep existing but optimized)
def create_object_id() -> ObjectId:
    """Create a new MongoDB ObjectId"""
    return ObjectId()


def is_valid_object_id(obj_id: str) -> bool:
    """Check if string is a valid ObjectId"""
    try:
        ObjectId(obj_id)
        return True
    except (InvalidId, TypeError):
        return False


# OPTIMIZED: Bulk operations for better performance
async def bulk_insert_documents_optimized(documents: List[Dict[str, Any]], ordered: bool = False) -> Dict[str, Any]:
    """OPTIMIZED bulk insert with better error handling and performance"""
    if not documents:
        return {"inserted_count": 0, "errors": []}
    
    try:
        collection = get_documents_collection()
        
        # OPTIMIZED: Use unordered inserts for better performance (parallel execution)
        result = await collection.insert_many(documents, ordered=ordered)
        
        return {
            "inserted_count": len(result.inserted_ids),
            "inserted_ids": [str(oid) for oid in result.inserted_ids],
            "errors": []
        }
        
    except BulkWriteError as e:
        # Handle partial success in bulk operations
        inserted_count = e.details.get("nInserted", 0)
        errors = []
        
        for error in e.details.get("writeErrors", []):
            errors.append({
                "index": error["index"],
                "code": error["code"],
                "message": error["errmsg"]
            })
        
        return {
            "inserted_count": inserted_count,
            "errors": errors
        }
    except Exception as e:
        logger.error(f"Bulk insert failed: {e}")
        return {
            "inserted_count": 0,
            "errors": [{"message": str(e)}]
        }


# OPTIMIZED: Audit logging with better performance
async def log_audit_event(
    action: AuditAction,
    user_id: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None,
    ip_address: Optional[str] = None,
    correlation_id: Optional[str] = None
) -> None:
    """Log audit event to database with performance optimization"""
    try:
        collection = get_audit_logs_collection()
        
        # OPTIMIZED: Pre-structure the document for better insert performance
        audit_doc = {
            "action": action.value if hasattr(action, 'value') else str(action),
            "user_id": user_id,
            "details": details or {},
            "ip_address": ip_address,
            "correlation_id": correlation_id,
            "timestamp": datetime.now(timezone.utc)
        }
        
        # OPTIMIZED: Use fire-and-forget insert for audit logs (better performance)
        # Don't wait for result unless in test mode
        if settings.test_mode:
            await collection.insert_one(audit_doc)
        else:
            # Fire and forget for production performance
            asyncio.create_task(collection.insert_one(audit_doc))
        
    except Exception as e:
        # Don't fail the main operation if audit logging fails
        logger.error(f"Failed to log audit event: {e}")


# OPTIMIZED: Search functions with better performance
async def search_documents_optimized(
    query: str,
    user_id: str,
    filters: Optional[Dict[str, Any]] = None,
    page: int = 1,
    page_size: int = 20,
    use_text_search: bool = True
) -> Tuple[List[Dict[str, Any]], int]:
    """OPTIMIZED document search with text indexes and filters"""
    try:
        collection = get_documents_collection()
        
        # Build search query
        search_query = {"user_id": user_id}
        
        # Add filters
        if filters:
            search_query.update(filters)
        
        if query and use_text_search:
            # OPTIMIZED: Use text search index for better performance
            search_query["$text"] = {"$search": query}
            
            # Use aggregation with text score for relevance
            pipeline = [
                {"$match": search_query},
                {"$addFields": {"score": {"$meta": "textScore"}}},
                {"$sort": {"score": {"$meta": "textScore"}, "created_at": DESCENDING}},
                {
                    "$facet": {
                        "data": [
                            {"$skip": (page - 1) * page_size},
                            {"$limit": page_size}
                        ],
                        "total": [{"$count": "count"}]
                    }
                }
            ]
            
            cursor = collection.aggregate(pipeline)
            result = await asyncio.wait_for(cursor.to_list(1), timeout=30.0)
            
        else:
            # OPTIMIZED: Use the optimized pagination function
            result_items, total_count = await paginate_query_optimized(
                collection=collection,
                query=search_query,
                page=page,
                page_size=page_size,
                sort_by="created_at",
                sort_order=DESCENDING,
                use_cursor=False
            )[:2]  # Only take first two elements
            
            return result_items, total_count
        
        if not result:
            return [], 0
        
        items = result[0]["data"]
        total_count = result[0]["total"][0]["count"] if result[0]["total"] else 0
        
        return items, total_count
        
    except Exception as e:
        logger.error(f"Document search failed: {e}")
        return [], 0


# Keep existing search function for compatibility
async def search_documents(query: str, user_id: str, page: int = 1, page_size: int = 20) -> List[Dict[str, Any]]:
    """Legacy search function - uses optimized version internally"""
    items, _ = await search_documents_optimized(
        query=query,
        user_id=user_id,
        page=page,
        page_size=page_size
    )
    return items


# Data validation utilities
def validate_user_data(user_data: Dict[str, Any]) -> bool:
    """Validate user data before database insertion"""
    required_fields = ["email", "password_hash", "role"]
    
    if not all(field in user_data for field in required_fields):
        return False
    
    # Additional validation
    if not isinstance(user_data.get("role"), (str, UserRole)):
        return False
    
    if len(user_data.get("email", "")) < 3:
        return False
    
    return True


def validate_document_data(document_data: Dict[str, Any]) -> bool:
    """Validate document data before database insertion"""
    required_fields = ["name", "hash", "size", "user_id"]
    
    if not all(field in document_data for field in required_fields):
        return False
    
    # Additional validation
    if not isinstance(document_data.get("size"), int) or document_data["size"] <= 0:
        return False
    
    if not isinstance(document_data.get("hash"), str) or len(document_data["hash"]) != 64:
        return False
    
    return True


# Test utilities (optimized for test mode)
async def drop_test_collections() -> None:
    """Drop all test collections - optimized for test cleanup"""
    if not settings.test_mode:
        raise RuntimeError("Can only drop collections in test mode")
    
    try:
        collections = await database.database.list_collection_names()
        
        # OPTIMIZED: Drop collections in parallel
        drop_tasks = []
        for collection_name in collections:
            if not collection_name.startswith('system.'):
                task = database.database[collection_name].drop()
                drop_tasks.append(task)
        
        if drop_tasks:
            await asyncio.gather(*drop_tasks, return_exceptions=True)
            
        logger.info(f"Dropped {len(drop_tasks)} test collections")
        
    except Exception as e:
        logger.error(f"Failed to drop test collections: {e}")
        raise


# Migration utilities (for future use)
async def get_database_version() -> Optional[str]:
    """Get current database schema version"""
    try:
        collection = database.database["_schema_version"]
        doc = await collection.find_one({})
        return doc.get("version") if doc else None
    except Exception as e:
        logger.error(f"Failed to get database version: {e}")
        return None


async def set_database_version(version: str) -> None:
    """Set database schema version"""
    try:
        collection = database.database["_schema_version"]
        await collection.replace_one(
            {},
            {"version": version, "updated_at": datetime.now(timezone.utc)},
            upsert=True
        )
        logger.info(f"Database schema version set to: {version}")
    except Exception as e:
        logger.error(f"Failed to set database version: {e}")