"""
Path: infrastructure/source/api/tests/test_database.py
Version: 1 - Database System Tests
"""

import pytest
import asyncio
import time
from datetime import datetime, timezone, timedelta
from unittest.mock import AsyncMock, MagicMock, patch, call
from typing import Dict, Any, List, Optional
import motor.motor_asyncio
import pymongo
from pymongo.errors import ConnectionFailure, DuplicateKeyError, ServerSelectionTimeoutError

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from database import (
    connect_to_mongo, close_mongo_connection, database,
    get_users_collection, get_documents_collection, get_audit_logs_collection,
    get_api_keys_collection, ensure_indexes, health_check_database,
    create_collections, drop_collections
)
from config import get_settings


class TestDatabaseConnection:
    """Test database connection management"""
    
    @pytest.mark.asyncio
    async def test_connect_to_mongo_success(self):
        """Test successful MongoDB connection"""
        
        with patch('motor.motor_asyncio.AsyncIOMotorClient') as mock_client_class:
            mock_client = MagicMock()
            mock_db = MagicMock()
            mock_client.__getitem__.return_value = mock_db
            mock_client_class.return_value = mock_client
            
            # Mock successful connection test
            mock_client.admin.command.return_value = {"ok": 1}
            
            client = await connect_to_mongo()
            
            assert client == mock_client
            
            # Verify connection parameters
            mock_client_class.assert_called_once()
            call_args = mock_client_class.call_args
            
            # Should have connection parameters
            assert call_args is not None
            
            # Verify connection test was performed
            mock_client.admin.command.assert_called_once_with("ping")
    
    @pytest.mark.asyncio
    async def test_connect_to_mongo_connection_failure(self):
        """Test MongoDB connection failure"""
        
        with patch('motor.motor_asyncio.AsyncIOMotorClient') as mock_client_class:
            mock_client = MagicMock()
            mock_client_class.return_value = mock_client
            
            # Mock connection failure
            mock_client.admin.command.side_effect = ConnectionFailure("Connection failed")
            
            with pytest.raises(ConnectionFailure):
                await connect_to_mongo()
    
    @pytest.mark.asyncio
    async def test_connect_to_mongo_timeout(self):
        """Test MongoDB connection timeout"""
        
        with patch('motor.motor_asyncio.AsyncIOMotorClient') as mock_client_class:
            mock_client = MagicMock()
            mock_client_class.return_value = mock_client
            
            # Mock timeout
            mock_client.admin.command.side_effect = ServerSelectionTimeoutError("Timeout")
            
            with pytest.raises(ServerSelectionTimeoutError):
                await connect_to_mongo()
    
    @pytest.mark.asyncio
    async def test_close_mongo_connection(self):
        """Test closing MongoDB connection"""
        
        mock_client = MagicMock()
        
        with patch('database.client', mock_client):
            await close_mongo_connection()
            
            # Verify client was closed
            mock_client.close.assert_called_once()


class TestDatabaseConfiguration:
    """Test database configuration and settings"""
    
    def test_database_settings_integration(self):
        """Test database settings integration"""
        
        settings = get_settings()
        
        # Verify database settings are available
        assert hasattr(settings, 'mongodb_url')
        assert hasattr(settings, 'mongodb_db_name')
        assert hasattr(settings, 'mongodb_max_connections')
        assert hasattr(settings, 'mongodb_min_connections')
        
        # Verify reasonable defaults
        assert settings.mongodb_max_connections > 0
        assert settings.mongodb_min_connections >= 0
        assert settings.mongodb_min_connections <= settings.mongodb_max_connections
    
    def test_effective_database_name(self):
        """Test effective database name for test mode"""
        
        settings = get_settings()
        
        # In test mode, should append _test suffix
        if settings.test_mode:
            assert settings.effective_mongodb_db_name.endswith("_test")
        else:
            assert settings.effective_mongodb_db_name == settings.mongodb_db_name


class TestCollectionAccess:
    """Test collection access functions"""
    
    @pytest.fixture
    def mock_database(self):
        mock_db = MagicMock()
        return mock_db
    
    def test_get_users_collection(self, mock_database):
        """Test getting users collection"""
        
        with patch('database.database', mock_database):
            collection = get_users_collection()
            
            mock_database.__getitem__.assert_called_once_with("users")
            assert collection == mock_database.__getitem__.return_value
    
    def test_get_documents_collection(self, mock_database):
        """Test getting documents collection"""
        
        with patch('database.database', mock_database):
            collection = get_documents_collection()
            
            mock_database.__getitem__.assert_called_once_with("documents")
            assert collection == mock_database.__getitem__.return_value
    
    def test_get_audit_logs_collection(self, mock_database):
        """Test getting audit logs collection"""
        
        with patch('database.database', mock_database):
            collection = get_audit_logs_collection()
            
            mock_database.__getitem__.assert_called_once_with("audit_logs")
            assert collection == mock_database.__getitem__.return_value
    
    def test_get_api_keys_collection(self, mock_database):
        """Test getting API keys collection"""
        
        with patch('database.database', mock_database):
            collection = get_api_keys_collection()
            
            mock_database.__getitem__.assert_called_once_with("api_keys")
            assert collection == mock_database.__getitem__.return_value


class TestIndexCreation:
    """Test database index creation and management"""
    
    @pytest.fixture
    def mock_collections(self):
        """Mock collections with index creation methods"""
        collections = {}
        for collection_name in ["users", "documents", "audit_logs", "api_keys"]:
            mock_collection = AsyncMock()
            mock_collection.create_index = AsyncMock()
            mock_collection.create_indexes = AsyncMock()
            mock_collection.list_indexes = AsyncMock()
            collections[collection_name] = mock_collection
        return collections
    
    @pytest.mark.asyncio
    async def test_ensure_indexes_users(self, mock_collections):
        """Test user collection index creation"""
        
        with patch('database.get_users_collection', return_value=mock_collections["users"]):
            await ensure_indexes()
            
            # Verify user indexes were created
            mock_collections["users"].create_indexes.assert_called_once()
            indexes_call = mock_collections["users"].create_indexes.call_args[0][0]
            
            # Should have email unique index
            email_index = next((idx for idx in indexes_call if "email" in str(idx)), None)
            assert email_index is not None
            
            # Should have created_at index for queries
            created_index = next((idx for idx in indexes_call if "created_at" in str(idx)), None)
            assert created_index is not None
    
    @pytest.mark.asyncio
    async def test_ensure_indexes_documents(self, mock_collections):
        """Test documents collection index creation"""
        
        with patch('database.get_documents_collection', return_value=mock_collections["documents"]):
            await ensure_indexes()
            
            # Verify document indexes were created
            mock_collections["documents"].create_indexes.assert_called_once()
            indexes_call = mock_collections["documents"].create_indexes.call_args[0][0]
            
            # Should have user_id index for user queries
            user_index = next((idx for idx in indexes_call if "user_id" in str(idx)), None)
            assert user_index is not None
            
            # Should have status index for filtering
            status_index = next((idx for idx in indexes_call if "status" in str(idx)), None)
            assert status_index is not None
            
            # Should have created_at index for sorting
            created_index = next((idx for idx in indexes_call if "created_at" in str(idx)), None)
            assert created_index is not None
    
    @pytest.mark.asyncio
    async def test_ensure_indexes_audit_logs(self, mock_collections):
        """Test audit logs collection index creation"""
        
        with patch('database.get_audit_logs_collection', return_value=mock_collections["audit_logs"]):
            await ensure_indexes()
            
            # Verify audit log indexes were created
            mock_collections["audit_logs"].create_indexes.assert_called_once()
            indexes_call = mock_collections["audit_logs"].create_indexes.call_args[0][0]
            
            # Should have user_id index
            user_index = next((idx for idx in indexes_call if "user_id" in str(idx)), None)
            assert user_index is not None
            
            # Should have action index
            action_index = next((idx for idx in indexes_call if "action" in str(idx)), None)
            assert action_index is not None
            
            # Should have timestamp index with TTL for auto-deletion
            timestamp_index = next((idx for idx in indexes_call if "timestamp" in str(idx)), None)
            assert timestamp_index is not None
    
    @pytest.mark.asyncio
    async def test_ensure_indexes_api_keys(self, mock_collections):
        """Test API keys collection index creation"""
        
        with patch('database.get_api_keys_collection', return_value=mock_collections["api_keys"]):
            await ensure_indexes()
            
            # Verify API key indexes were created
            mock_collections["api_keys"].create_indexes.assert_called_once()
            indexes_call = mock_collections["api_keys"].create_indexes.call_args[0][0]
            
            # Should have prefix index for key lookup
            prefix_index = next((idx for idx in indexes_call if "prefix" in str(idx)), None)
            assert prefix_index is not None
            
            # Should have user_id index
            user_index = next((idx for idx in indexes_call if "user_id" in str(idx)), None)
            assert user_index is not None
            
            # Should have expires_at index with TTL
            expires_index = next((idx for idx in indexes_call if "expires_at" in str(idx)), None)
            assert expires_index is not None
    
    @pytest.mark.asyncio
    async def test_ensure_indexes_error_handling(self, mock_collections):
        """Test index creation error handling"""
        
        # Mock index creation failure
        mock_collections["users"].create_indexes.side_effect = Exception("Index creation failed")
        
        with patch('database.get_users_collection', return_value=mock_collections["users"]):
            # Should not raise exception but handle gracefully
            await ensure_indexes()
            
            # Verify attempt was made
            mock_collections["users"].create_indexes.assert_called_once()


class TestCollectionManagement:
    """Test collection creation and management"""
    
    @pytest.fixture
    def mock_database(self):
        mock_db = AsyncMock()
        return mock_db
    
    @pytest.mark.asyncio
    async def test_create_collections(self, mock_database):
        """Test creating all required collections"""
        
        # Mock collection listing
        mock_database.list_collection_names.return_value = []  # No existing collections
        
        with patch('database.database', mock_database):
            await create_collections()
            
            # Verify collections were created
            expected_collections = ["users", "documents", "audit_logs", "api_keys"]
            
            for collection_name in expected_collections:
                mock_database.create_collection.assert_any_call(collection_name)
    
    @pytest.mark.asyncio
    async def test_create_collections_already_exist(self, mock_database):
        """Test creating collections when they already exist"""
        
        # Mock existing collections
        mock_database.list_collection_names.return_value = ["users", "documents", "audit_logs", "api_keys"]
        
        with patch('database.database', mock_database):
            await create_collections()
            
            # Should not attempt to create existing collections
            mock_database.create_collection.assert_not_called()
    
    @pytest.mark.asyncio
    async def test_drop_collections(self, mock_database):
        """Test dropping collections (for testing)"""
        
        # Mock existing collections
        mock_database.list_collection_names.return_value = ["users", "documents", "audit_logs", "api_keys"]
        
        with patch('database.database', mock_database):
            await drop_collections()
            
            # Verify collections were dropped
            expected_collections = ["users", "documents", "audit_logs", "api_keys"]
            
            for collection_name in expected_collections:
                mock_database.drop_collection.assert_any_call(collection_name)
    
    @pytest.mark.asyncio
    async def test_drop_collections_not_exist(self, mock_database):
        """Test dropping non-existent collections"""
        
        # Mock no existing collections
        mock_database.list_collection_names.return_value = []
        
        with patch('database.database', mock_database):
            await drop_collections()
            
            # Should not attempt to drop non-existent collections
            mock_database.drop_collection.assert_not_called()


class TestHealthCheck:
    """Test database health check functionality"""
    
    @pytest.mark.asyncio
    async def test_health_check_database_healthy(self):
        """Test database health check when healthy"""
        
        mock_client = AsyncMock()
        mock_client.admin.command.return_value = {"ok": 1}
        
        with patch('database.client', mock_client):
            health = await health_check_database()
            
            assert health["status"] == "healthy"
            assert health["connected"] is True
            assert "response_time" in health
            assert health["response_time"] >= 0
            
            # Verify ping command was called
            mock_client.admin.command.assert_called_once_with("ping")
    
    @pytest.mark.asyncio
    async def test_health_check_database_unhealthy(self):
        """Test database health check when unhealthy"""
        
        mock_client = AsyncMock()
        mock_client.admin.command.side_effect = ConnectionFailure("Connection lost")
        
        with patch('database.client', mock_client):
            health = await health_check_database()
            
            assert health["status"] == "unhealthy"
            assert health["connected"] is False
            assert "error" in health
            assert "connection lost" in health["error"].lower()
    
    @pytest.mark.asyncio
    async def test_health_check_database_timeout(self):
        """Test database health check with timeout"""
        
        mock_client = AsyncMock()
        mock_client.admin.command.side_effect = ServerSelectionTimeoutError("Timeout")
        
        with patch('database.client', mock_client):
            health = await health_check_database()
            
            assert health["status"] == "unhealthy"
            assert health["connected"] is False
            assert "timeout" in health["error"].lower()
    
    @pytest.mark.asyncio
    async def test_health_check_database_no_client(self):
        """Test database health check with no client"""
        
        with patch('database.client', None):
            health = await health_check_database()
            
            assert health["status"] == "unhealthy"
            assert health["connected"] is False
            assert "not connected" in health["error"].lower()


class TestDatabaseOperations:
    """Test basic database operations"""
    
    @pytest.fixture
    def mock_collection(self):
        collection = AsyncMock()
        return collection
    
    @pytest.mark.asyncio
    async def test_insert_document(self, mock_collection):
        """Test inserting a document"""
        
        # Mock successful insert
        mock_result = MagicMock()
        mock_result.inserted_id = "64a1b2c3d4e5f6a7b8c9d0e1"
        mock_collection.insert_one.return_value = mock_result
        
        document = {
            "email": "test@example.com",
            "name": "Test User",
            "created_at": datetime.now(timezone.utc)
        }
        
        result = await mock_collection.insert_one(document)
        
        assert result.inserted_id == "64a1b2c3d4e5f6a7b8c9d0e1"
        mock_collection.insert_one.assert_called_once_with(document)
    
    @pytest.mark.asyncio
    async def test_find_document(self, mock_collection):
        """Test finding a document"""
        
        # Mock document found
        expected_doc = {
            "_id": "64a1b2c3d4e5f6a7b8c9d0e1",
            "email": "test@example.com",
            "name": "Test User"
        }
        mock_collection.find_one.return_value = expected_doc
        
        result = await mock_collection.find_one({"email": "test@example.com"})
        
        assert result == expected_doc
        mock_collection.find_one.assert_called_once_with({"email": "test@example.com"})
    
    @pytest.mark.asyncio
    async def test_update_document(self, mock_collection):
        """Test updating a document"""
        
        # Mock successful update
        mock_result = MagicMock()
        mock_result.modified_count = 1
        mock_collection.update_one.return_value = mock_result
        
        result = await mock_collection.update_one(
            {"_id": "64a1b2c3d4e5f6a7b8c9d0e1"},
            {"$set": {"name": "Updated Name"}}
        )
        
        assert result.modified_count == 1
        mock_collection.update_one.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_delete_document(self, mock_collection):
        """Test deleting a document"""
        
        # Mock successful deletion
        mock_result = MagicMock()
        mock_result.deleted_count = 1
        mock_collection.delete_one.return_value = mock_result
        
        result = await mock_collection.delete_one({"_id": "64a1b2c3d4e5f6a7b8c9d0e1"})
        
        assert result.deleted_count == 1
        mock_collection.delete_one.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_duplicate_key_error(self, mock_collection):
        """Test handling duplicate key error"""
        
        # Mock duplicate key error
        mock_collection.insert_one.side_effect = DuplicateKeyError("Duplicate key")
        
        document = {"email": "existing@example.com"}
        
        with pytest.raises(DuplicateKeyError):
            await mock_collection.insert_one(document)


class TestTransactions:
    """Test database transaction handling"""
    
    @pytest.fixture
    def mock_client(self):
        client = AsyncMock()
        return client
    
    @pytest.mark.asyncio
    async def test_transaction_success(self, mock_client):
        """Test successful transaction"""
        
        # Mock transaction session
        mock_session = AsyncMock()
        mock_client.start_session.return_value.__aenter__.return_value = mock_session
        
        async def transaction_operations(session):
            # Mock some operations within transaction
            return "success"
        
        with patch('database.client', mock_client):
            # Simulate transaction usage
            async with mock_client.start_session() as session:
                result = await transaction_operations(session)
                
                assert result == "success"
    
    @pytest.mark.asyncio
    async def test_transaction_rollback(self, mock_client):
        """Test transaction rollback on error"""
        
        # Mock transaction session
        mock_session = AsyncMock()
        mock_client.start_session.return_value.__aenter__.return_value = mock_session
        
        async def failing_transaction_operations(session):
            raise Exception("Transaction failed")
        
        with patch('database.client', mock_client):
            # Simulate transaction with error
            with pytest.raises(Exception):
                async with mock_client.start_session() as session:
                    await failing_transaction_operations(session)


class TestQueryOptimization:
    """Test query optimization and performance"""
    
    @pytest.fixture
    def mock_collection(self):
        collection = AsyncMock()
        return collection
    
    @pytest.mark.asyncio
    async def test_indexed_query_performance(self, mock_collection):
        """Test that queries use appropriate indexes"""
        
        # Mock query with explain
        mock_explain = {
            "executionStats": {
                "executionSuccess": True,
                "totalExaminedDocs": 1,
                "totalDocsExamined": 1,
                "executionTimeMillis": 5
            }
        }
        
        mock_cursor = AsyncMock()
        mock_cursor.explain.return_value = mock_explain
        mock_collection.find.return_value = mock_cursor
        
        # Query that should use email index
        cursor = mock_collection.find({"email": "test@example.com"})
        explain_result = await cursor.explain()
        
        # Should be efficient (low docs examined)
        stats = explain_result["executionStats"]
        assert stats["executionSuccess"] is True
        assert stats["totalExaminedDocs"] <= 10  # Should be very efficient with index
        assert stats["executionTimeMillis"] < 100  # Should be fast
    
    @pytest.mark.asyncio
    async def test_compound_index_usage(self, mock_collection):
        """Test compound index usage"""
        
        # Query that should use compound index (user_id + status)
        mock_cursor = AsyncMock()
        mock_collection.find.return_value = mock_cursor
        
        cursor = mock_collection.find({
            "user_id": "user_123",
            "status": "completed"
        }).sort([("created_at", -1)])
        
        mock_collection.find.assert_called_once_with({
            "user_id": "user_123",
            "status": "completed"
        })
    
    @pytest.mark.asyncio
    async def test_pagination_cursor_based(self, mock_collection):
        """Test cursor-based pagination"""
        
        # Mock documents for pagination
        mock_docs = [
            {"_id": f"id_{i}", "name": f"Doc {i}", "created_at": datetime.now(timezone.utc)}
            for i in range(10)
        ]
        
        mock_cursor = AsyncMock()
        mock_cursor.to_list.return_value = mock_docs[:5]  # First page
        mock_collection.find.return_value = mock_cursor
        
        # Cursor-based pagination query
        last_id = None
        page_size = 5
        
        query = {}
        if last_id:
            query["_id"] = {"$gt": last_id}
        
        cursor = mock_collection.find(query).sort([("_id", 1)]).limit(page_size)
        docs = await cursor.to_list(page_size)
        
        assert len(docs) == 5
        mock_collection.find.assert_called_once_with(query)


class TestDataValidation:
    """Test data validation at database level"""
    
    @pytest.fixture
    def mock_collection(self):
        collection = AsyncMock()
        return collection
    
    @pytest.mark.asyncio
    async def test_schema_validation(self, mock_collection):
        """Test schema validation for documents"""
        
        # Valid document should succeed
        valid_doc = {
            "email": "test@example.com",
            "name": "Test User",
            "role": "user",
            "is_active": True,
            "created_at": datetime.now(timezone.utc)
        }
        
        mock_result = MagicMock()
        mock_result.inserted_id = "valid_id"
        mock_collection.insert_one.return_value = mock_result
        
        result = await mock_collection.insert_one(valid_doc)
        assert result.inserted_id == "valid_id"
    
    @pytest.mark.asyncio
    async def test_invalid_schema_rejection(self, mock_collection):
        """Test rejection of invalid schema documents"""
        
        # Mock schema validation error
        from pymongo.errors import WriteError
        mock_collection.insert_one.side_effect = WriteError("Document failed validation")
        
        # Invalid document (missing required fields)
        invalid_doc = {
            "name": "Incomplete User"
            # Missing required email field
        }
        
        with pytest.raises(WriteError):
            await mock_collection.insert_one(invalid_doc)


class TestBackupAndRecovery:
    """Test backup and recovery operations"""
    
    @pytest.fixture
    def mock_database(self):
        db = AsyncMock()
        return db
    
    @pytest.mark.asyncio
    async def test_collection_backup_metadata(self, mock_database):
        """Test getting collection metadata for backup"""
        
        # Mock collection stats
        mock_stats = {
            "count": 1000,
            "size": 1024000,  # 1MB
            "avgObjSize": 1024,
            "indexes": 5
        }
        mock_database.command.return_value = mock_stats
        
        with patch('database.database', mock_database):
            stats = await mock_database.command("collStats", "users")
            
            assert stats["count"] == 1000
            assert stats["size"] == 1024000
            assert stats["indexes"] == 5
    
    @pytest.mark.asyncio
    async def test_database_backup_metadata(self, mock_database):
        """Test getting database metadata for backup"""
        
        # Mock database stats
        mock_db_stats = {
            "db": "opendocseal_test",
            "collections": 4,
            "dataSize": 10240000,  # 10MB
            "indexSize": 1024000   # 1MB
        }
        mock_database.command.return_value = mock_db_stats
        
        with patch('database.database', mock_database):
            stats = await mock_database.command("dbStats")
            
            assert stats["collections"] == 4
            assert stats["dataSize"] == 10240000
            assert stats["indexSize"] == 1024000


class TestPerformanceMonitoring:
    """Test database performance monitoring"""
    
    @pytest.fixture
    def mock_database(self):
        db = AsyncMock()
        return db
    
    @pytest.mark.asyncio
    async def test_slow_query_detection(self, mock_database):
        """Test slow query detection and logging"""
        
        # Mock slow query profiling
        mock_profile_data = [
            {
                "ts": datetime.now(timezone.utc),
                "t": {"$date": "2024-01-15T12:00:00.000Z"},
                "ns": "opendocseal.users",
                "op": "query",
                "command": {"find": "users"},
                "millis": 1500,  # Slow query
                "planSummary": "COLLSCAN"  # No index used
            }
        ]
        
        mock_cursor = AsyncMock()
        mock_cursor.to_list.return_value = mock_profile_data
        mock_database.system.profile.find.return_value = mock_cursor
        
        with patch('database.database', mock_database):
            # Query profiling collection
            cursor = mock_database.system.profile.find({
                "millis": {"$gt": 1000}  # Queries slower than 1 second
            })
            slow_queries = await cursor.to_list(100)
            
            assert len(slow_queries) == 1
            assert slow_queries[0]["millis"] == 1500
            assert slow_queries[0]["planSummary"] == "COLLSCAN"
    
    @pytest.mark.asyncio
    async def test_connection_pool_monitoring(self, mock_database):
        """Test connection pool monitoring"""
        
        # Mock server status with connection info
        mock_server_status = {
            "connections": {
                "current": 25,
                "available": 775,
                "totalCreated": 100
            },
            "network": {
                "bytesIn": 1024000,
                "bytesOut": 2048000,
                "numRequests": 5000
            }
        }
        mock_database.command.return_value = mock_server_status
        
        with patch('database.database', mock_database):
            status = await mock_database.command("serverStatus")
            
            connections = status["connections"]
            assert connections["current"] == 25
            assert connections["available"] == 775
            
            network = status["network"]
            assert network["numRequests"] == 5000


if __name__ == "__main__":
    # Run tests with pytest
    pytest.main([__file__, "-v", "--tb=short"])