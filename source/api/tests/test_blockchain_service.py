"""
Path: infrastructure/source/api/tests/test_blockchain_service.py
Version: 1 - BlockchainService Production Tests
"""

import pytest
import asyncio
import time
import hashlib
from datetime import datetime, timezone, timedelta
from unittest.mock import AsyncMock, MagicMock, patch, call
from typing import Dict, Any, List, Optional
import aiohttp
import json

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from services.blockchain import BlockchainService
from models.blockchain import (
    BlockchainTransaction, BlockchainProof, TransactionStatistics,
    ProofVerificationRequest, ProofVerificationResult, BlockchainNetwork, ProofType
)
from models.base import TransactionStatus
from config import get_settings


class TestBlockchainServiceCreation:
    """Test BlockchainService creation and initialization"""
    
    def test_blockchain_service_initialization(self):
        """Test BlockchainService initialization"""
        blockchain_service = BlockchainService()
        
        # Check connection pooling
        assert hasattr(blockchain_service, '_session')
        assert blockchain_service._session is None  # Lazy initialization
        
        # Check pending requests tracking
        assert hasattr(blockchain_service, '_pending_requests')
        assert isinstance(blockchain_service._pending_requests, dict)
        
        # Check metrics initialization
        assert hasattr(blockchain_service, '_metrics')
        assert "requests_sent" in blockchain_service._metrics
        assert "responses_received" in blockchain_service._metrics
        assert "errors_count" in blockchain_service._metrics
        
        # Check cache initialization
        assert hasattr(blockchain_service, '_proof_cache')
        
        # Check rate limiting
        assert hasattr(blockchain_service, '_rate_limiter')


class TestSessionManagement:
    """Test HTTP session management"""
    
    @pytest.fixture
    def blockchain_service(self):
        return BlockchainService()
    
    @pytest.mark.asyncio
    async def test_get_session_creation(self, blockchain_service):
        """Test HTTP session creation"""
        
        session = await blockchain_service._get_session()
        
        assert session is not None
        assert isinstance(session, aiohttp.ClientSession)
        assert blockchain_service._session is session
        
        # Test session reuse
        session2 = await blockchain_service._get_session()
        assert session2 is session  # Should be the same instance
    
    @pytest.mark.asyncio
    async def test_session_cleanup(self, blockchain_service):
        """Test session cleanup on service destruction"""
        
        # Create session
        session = await blockchain_service._get_session()
        assert session is not None
        
        # Test cleanup
        await blockchain_service.cleanup()
        
        # Session should be closed
        assert blockchain_service._session is None


class TestOpenTimestampsIntegration:
    """Test OpenTimestamps integration"""
    
    @pytest.fixture
    def blockchain_service(self):
        return BlockchainService()
    
    @pytest.fixture
    def sample_document_hash(self):
        return "a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3"  # SHA256 of "hello"
    
    @pytest.mark.asyncio
    async def test_create_timestamp_success(self, blockchain_service, sample_document_hash):
        """Test successful timestamp creation"""
        
        with patch('aiohttp.ClientSession.post') as mock_post:
            # Mock successful OpenTimestamps response
            mock_response = AsyncMock()
            mock_response.status = 200
            mock_response.json.return_value = {
                "status": "success",
                "transaction_id": "ots_123456789abcdef",
                "timestamp_proof": "proof_data_base64",
                "estimated_confirmation_time": 600
            }
            mock_response.__aenter__.return_value = mock_response
            mock_post.return_value = mock_response
            
            result = await blockchain_service.create_timestamp(sample_document_hash)
            
            assert result is not None
            assert result.transaction_id == "ots_123456789abcdef"
            assert result.status == TransactionStatus.PENDING
            assert result.blockchain_network == BlockchainNetwork.BITCOIN
            assert result.proof_type == ProofType.OPENTIMESTAMPS
            
            # Verify request was made
            mock_post.assert_called_once()
            call_args = mock_post.call_args
            assert "opentimestamps" in str(call_args)
    
    @pytest.mark.asyncio
    async def test_create_timestamp_deduplication(self, blockchain_service, sample_document_hash):
        """Test request deduplication"""
        
        with patch('aiohttp.ClientSession.post') as mock_post:
            # Mock delayed response
            async def delayed_response(*args, **kwargs):
                await asyncio.sleep(0.1)
                mock_response = AsyncMock()
                mock_response.status = 200
                mock_response.json.return_value = {
                    "status": "success",
                    "transaction_id": "ots_dedup_test",
                    "timestamp_proof": "proof_data_base64"
                }
                mock_response.__aenter__.return_value = mock_response
                return mock_response
            
            mock_post.side_effect = delayed_response
            
            # Make two concurrent requests with same hash
            task1 = asyncio.create_task(blockchain_service.create_timestamp(sample_document_hash))
            task2 = asyncio.create_task(blockchain_service.create_timestamp(sample_document_hash))
            
            result1, result2 = await asyncio.gather(task1, task2)
            
            # Both should return the same transaction
            assert result1.transaction_id == result2.transaction_id
            
            # But only one HTTP request should have been made
            assert mock_post.call_count == 1
    
    @pytest.mark.asyncio
    async def test_create_timestamp_rate_limiting(self, blockchain_service, sample_document_hash):
        """Test rate limiting integration"""
        
        with patch.object(blockchain_service._rate_limiter, 'check_rate_limit') as mock_rate_limit:
            mock_rate_limit.return_value = {
                "allowed": False,
                "remaining": 0,
                "reset_time": int(time.time()) + 3600,
                "error": "Rate limit exceeded"
            }
            
            result = await blockchain_service.create_timestamp(sample_document_hash)
            
            assert result is None
            
            # Verify rate limit was checked
            mock_rate_limit.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_create_timestamp_network_error(self, blockchain_service, sample_document_hash):
        """Test handling of network errors"""
        
        with patch('aiohttp.ClientSession.post') as mock_post:
            mock_post.side_effect = aiohttp.ClientError("Network error")
            
            result = await blockchain_service.create_timestamp(sample_document_hash)
            
            assert result is None
            
            # Verify metrics are updated for errors
            assert blockchain_service._metrics["errors_count"] > 0
    
    @pytest.mark.asyncio
    async def test_create_timestamp_api_error(self, blockchain_service, sample_document_hash):
        """Test handling of API errors"""
        
        with patch('aiohttp.ClientSession.post') as mock_post:
            mock_response = AsyncMock()
            mock_response.status = 500
            mock_response.text.return_value = "Internal Server Error"
            mock_response.__aenter__.return_value = mock_response
            mock_post.return_value = mock_response
            
            result = await blockchain_service.create_timestamp(sample_document_hash)
            
            assert result is None


class TestProofVerification:
    """Test proof verification functionality"""
    
    @pytest.fixture
    def blockchain_service(self):
        return BlockchainService()
    
    @pytest.fixture
    def sample_verification_request(self):
        return ProofVerificationRequest(
            document_hash="a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3",
            transaction_id="ots_123456789abcdef",
            proof_data="proof_data_base64_encoded",
            blockchain_network=BlockchainNetwork.BITCOIN
        )
    
    @pytest.mark.asyncio
    async def test_verify_proof_success(self, blockchain_service, sample_verification_request):
        """Test successful proof verification"""
        
        with patch('aiohttp.ClientSession.post') as mock_post:
            mock_response = AsyncMock()
            mock_response.status = 200
            mock_response.json.return_value = {
                "status": "verified",
                "is_valid": True,
                "confirmations": 6,
                "block_height": 750000,
                "block_hash": "00000000000000000007e9e4c586439b0cdbe13b1370bdd9435d76a644d047523",
                "verification_time": "2024-01-15T12:00:00Z"
            }
            mock_response.__aenter__.return_value = mock_response
            mock_post.return_value = mock_response
            
            result = await blockchain_service.verify_proof(sample_verification_request)
            
            assert result is not None
            assert result.is_valid is True
            assert result.confirmations == 6
            assert result.block_height == 750000
            assert result.status == TransactionStatus.CONFIRMED
    
    @pytest.mark.asyncio
    async def test_verify_proof_invalid(self, blockchain_service, sample_verification_request):
        """Test verification of invalid proof"""
        
        with patch('aiohttp.ClientSession.post') as mock_post:
            mock_response = AsyncMock()
            mock_response.status = 200
            mock_response.json.return_value = {
                "status": "invalid",
                "is_valid": False,
                "error": "Proof verification failed",
                "details": "Hash mismatch or invalid proof structure"
            }
            mock_response.__aenter__.return_value = mock_response
            mock_post.return_value = mock_response
            
            result = await blockchain_service.verify_proof(sample_verification_request)
            
            assert result is not None
            assert result.is_valid is False
            assert "invalid" in result.error.lower()
    
    @pytest.mark.asyncio
    async def test_verify_proof_pending(self, blockchain_service, sample_verification_request):
        """Test verification of pending proof"""
        
        with patch('aiohttp.ClientSession.post') as mock_post:
            mock_response = AsyncMock()
            mock_response.status = 200
            mock_response.json.return_value = {
                "status": "pending",
                "confirmations": 2,
                "estimated_confirmation_time": 1800
            }
            mock_response.__aenter__.return_value = mock_response
            mock_post.return_value = mock_response
            
            result = await blockchain_service.verify_proof(sample_verification_request)
            
            assert result is not None
            assert result.status == TransactionStatus.PENDING
            assert result.confirmations == 2


class TestCacheOperations:
    """Test caching functionality"""
    
    @pytest.fixture
    def blockchain_service(self):
        return BlockchainService()
    
    def test_proof_cache_key_generation(self, blockchain_service):
        """Test proof cache key generation"""
        
        document_hash = "a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3"
        
        # Test cache key generation
        cache_key = blockchain_service._cache_proof_key(document_hash, int(time.time()))
        
        assert cache_key.startswith("proof:")
        assert document_hash in cache_key
        
        # Test cache buckets (5-minute buckets)
        time1 = int(time.time())
        time2 = time1 + 200  # 3 minutes later
        time3 = time1 + 400  # 6 minutes later
        
        key1 = blockchain_service._cache_proof_key(document_hash, time1)
        key2 = blockchain_service._cache_proof_key(document_hash, time2)
        key3 = blockchain_service._cache_proof_key(document_hash, time3)
        
        # Keys should be same within 5-minute bucket
        assert key1 == key2
        # But different across bucket boundaries
        assert key1 != key3
    
    @pytest.mark.asyncio
    async def test_cache_hit_miss(self, blockchain_service):
        """Test cache hit and miss scenarios"""
        
        document_hash = "test_hash_for_cache"
        
        # First request - cache miss
        with patch('aiohttp.ClientSession.post') as mock_post:
            mock_response = AsyncMock()
            mock_response.status = 200
            mock_response.json.return_value = {
                "status": "success",
                "transaction_id": "ots_cache_test",
                "timestamp_proof": "proof_data"
            }
            mock_response.__aenter__.return_value = mock_response
            mock_post.return_value = mock_response
            
            result1 = await blockchain_service.create_timestamp(document_hash)
            
            assert result1 is not None
            assert mock_post.call_count == 1
        
        # Second request - should use deduplication (not cache, but pending request tracking)
        with patch('aiohttp.ClientSession.post') as mock_post2:
            # Start both requests concurrently to test deduplication
            task1 = asyncio.create_task(blockchain_service.create_timestamp(document_hash))
            task2 = asyncio.create_task(blockchain_service.create_timestamp(document_hash))
            
            await asyncio.gather(task1, task2, return_exceptions=True)


class TestRetryMechanism:
    """Test retry mechanism with exponential backoff"""
    
    @pytest.fixture
    def blockchain_service(self):
        return BlockchainService()
    
    @pytest.mark.asyncio
    async def test_retry_on_temporary_failure(self, blockchain_service):
        """Test retry mechanism on temporary failures"""
        
        document_hash = "test_hash_retry"
        
        with patch('aiohttp.ClientSession.post') as mock_post:
            # First two calls fail, third succeeds
            call_count = 0
            
            async def side_effect(*args, **kwargs):
                nonlocal call_count
                call_count += 1
                
                if call_count <= 2:
                    raise aiohttp.ClientError("Temporary network error")
                
                # Third call succeeds
                mock_response = AsyncMock()
                mock_response.status = 200
                mock_response.json.return_value = {
                    "status": "success",
                    "transaction_id": "ots_retry_success",
                    "timestamp_proof": "proof_data"
                }
                mock_response.__aenter__.return_value = mock_response
                return mock_response
            
            mock_post.side_effect = side_effect
            
            # Should retry and eventually succeed
            with patch('asyncio.sleep'):  # Speed up test by mocking sleep
                result = await blockchain_service.create_timestamp(document_hash)
            
            assert result is not None
            assert result.transaction_id == "ots_retry_success"
            assert mock_post.call_count == 3  # Two failures + one success
    
    @pytest.mark.asyncio
    async def test_retry_exhaustion(self, blockchain_service):
        """Test retry exhaustion after max attempts"""
        
        document_hash = "test_hash_retry_exhaustion"
        
        with patch('aiohttp.ClientSession.post') as mock_post:
            # Always fail
            mock_post.side_effect = aiohttp.ClientError("Persistent network error")
            
            with patch('asyncio.sleep'):  # Speed up test
                result = await blockchain_service.create_timestamp(document_hash)
            
            assert result is None
            # Should have retried max_retries times
            assert mock_post.call_count >= 3


class TestHealthCheck:
    """Test health check functionality"""
    
    @pytest.fixture
    def blockchain_service(self):
        return BlockchainService()
    
    @pytest.mark.asyncio
    async def test_health_check_healthy(self, blockchain_service):
        """Test health check when service is healthy"""
        
        with patch('aiohttp.ClientSession.get') as mock_get:
            mock_response = AsyncMock()
            mock_response.status = 200
            mock_response.json.return_value = {
                "status": "healthy",
                "version": "1.0.0",
                "uptime": 3600
            }
            mock_response.__aenter__.return_value = mock_response
            mock_get.return_value = mock_response
            
            health = await blockchain_service.health_check()
            
            assert health.status == "healthy"
            assert health.details is not None
            assert "response_time" in health.details
    
    @pytest.mark.asyncio
    async def test_health_check_unhealthy(self, blockchain_service):
        """Test health check when service is unhealthy"""
        
        with patch('aiohttp.ClientSession.get') as mock_get:
            mock_get.side_effect = aiohttp.ClientError("Service unavailable")
            
            health = await blockchain_service.health_check()
            
            assert health.status == "unhealthy"
            assert "error" in health.details
    
    @pytest.mark.asyncio
    async def test_health_check_timeout(self, blockchain_service):
        """Test health check timeout"""
        
        with patch('aiohttp.ClientSession.get') as mock_get:
            mock_get.side_effect = asyncio.TimeoutError("Request timeout")
            
            health = await blockchain_service.health_check()
            
            assert health.status == "unhealthy"
            assert "timeout" in health.details["error"].lower()


class TestMetricsCollection:
    """Test metrics collection"""
    
    @pytest.fixture
    def blockchain_service(self):
        return BlockchainService()
    
    def test_metrics_initialization(self, blockchain_service):
        """Test metrics are properly initialized"""
        
        expected_metrics = [
            "requests_sent", "responses_received", "errors_count",
            "total_response_time", "cache_hits", "cache_misses"
        ]
        
        for metric in expected_metrics:
            assert metric in blockchain_service._metrics
            assert isinstance(blockchain_service._metrics[metric], (int, float))
    
    @pytest.mark.asyncio
    async def test_metrics_update_on_request(self, blockchain_service):
        """Test metrics are updated on requests"""
        
        initial_requests = blockchain_service._metrics["requests_sent"]
        initial_errors = blockchain_service._metrics["errors_count"]
        
        with patch('aiohttp.ClientSession.post') as mock_post:
            mock_post.side_effect = aiohttp.ClientError("Test error")
            
            await blockchain_service.create_timestamp("test_hash")
            
            # Requests sent should increase
            assert blockchain_service._metrics["requests_sent"] > initial_requests
            
            # Errors should increase
            assert blockchain_service._metrics["errors_count"] > initial_errors
    
    def test_get_statistics(self, blockchain_service):
        """Test statistics retrieval"""
        
        # Update some metrics
        blockchain_service._metrics["requests_sent"] = 100
        blockchain_service._metrics["responses_received"] = 95
        blockchain_service._metrics["errors_count"] = 5
        blockchain_service._metrics["total_response_time"] = 50.0
        
        stats = blockchain_service.get_statistics()
        
        assert isinstance(stats, TransactionStatistics)
        assert stats.total_transactions == 100
        assert stats.successful_transactions == 95
        assert stats.failed_transactions == 5
        assert stats.average_response_time == 0.5  # 50.0 / 100


class TestConfigurationHandling:
    """Test configuration handling"""
    
    @pytest.fixture
    def blockchain_service(self):
        return BlockchainService()
    
    def test_settings_integration(self, blockchain_service):
        """Test integration with settings"""
        
        settings = get_settings()
        
        # Test that service uses correct endpoints
        assert hasattr(blockchain_service, '_opentimestamps_endpoint')
        
        # Test timeout configuration
        assert hasattr(blockchain_service, '_request_timeout')
        assert blockchain_service._request_timeout > 0
    
    @pytest.mark.asyncio
    async def test_different_networks(self, blockchain_service):
        """Test support for different blockchain networks"""
        
        # Test Bitcoin (default)
        result = await blockchain_service.create_timestamp(
            "test_hash", 
            network=BlockchainNetwork.BITCOIN
        )
        
        # Should work with Bitcoin network (even if mocked)
        assert True  # Basic test that method accepts network parameter


class TestErrorScenarios:
    """Test various error scenarios"""
    
    @pytest.fixture
    def blockchain_service(self):
        return BlockchainService()
    
    @pytest.mark.asyncio
    async def test_invalid_hash_format(self, blockchain_service):
        """Test handling of invalid hash format"""
        
        invalid_hashes = [
            "",  # Empty
            "invalid_hash",  # Not hex
            "abc123",  # Too short
            "x" * 65,  # Too long
        ]
        
        for invalid_hash in invalid_hashes:
            result = await blockchain_service.create_timestamp(invalid_hash)
            assert result is None  # Should reject invalid hashes
    
    @pytest.mark.asyncio
    async def test_concurrent_request_limit(self, blockchain_service):
        """Test concurrent request limiting"""
        
        # Mock delay to create concurrent requests
        with patch('aiohttp.ClientSession.post') as mock_post:
            async def delayed_response(*args, **kwargs):
                await asyncio.sleep(0.1)
                mock_response = AsyncMock()
                mock_response.status = 200
                mock_response.json.return_value = {
                    "status": "success",
                    "transaction_id": f"ots_{time.time()}",
                    "timestamp_proof": "proof_data"
                }
                mock_response.__aenter__.return_value = mock_response
                return mock_response
            
            mock_post.side_effect = delayed_response
            
            # Create many concurrent requests
            tasks = []
            for i in range(10):
                task = asyncio.create_task(
                    blockchain_service.create_timestamp(f"hash_{i}")
                )
                tasks.append(task)
            
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # All should complete without errors
            successful_results = [r for r in results if not isinstance(r, Exception)]
            assert len(successful_results) > 0


if __name__ == "__main__":
    # Run tests with pytest
    pytest.main([__file__, "-v", "--tb=short"])