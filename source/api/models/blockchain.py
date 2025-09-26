"""
Path: infrastructure/source/api/models/blockchain.py
Version: 2
"""

from datetime import datetime, timezone
from typing import Optional, Dict, Any, List
from pydantic import BaseModel, Field, field_validator, ConfigDict
from enum import Enum

from .base import BaseDocument, TransactionStatus


class BlockchainNetwork(str, Enum):
    """Supported blockchain networks"""
    BITCOIN_MAINNET = "bitcoin_mainnet"
    BITCOIN_TESTNET = "bitcoin_testnet"
    BITCOIN_REGTEST = "bitcoin_regtest"


class ProofType(str, Enum):
    """Types of cryptographic proofs"""
    OPENTIMESTAMPS = "opentimestamps"
    MERKLE_TREE = "merkle_tree"
    HASH_CHAIN = "hash_chain"


class BlockchainTransaction(BaseDocument):
    """Blockchain transaction model"""
    
    # FIXED: Updated to use model_config
    model_config = ConfigDict(
        populate_by_name=True,
        arbitrary_types_allowed=True,
        json_encoders={
            datetime: lambda v: v.isoformat()
        },
        json_schema_extra={
            "example": {
                "id": "507f1f77bcf86cd799439011",
                "document_id": "507f1f77bcf86cd799439012",
                "document_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "metadata_hash": "a4b2c33298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b900",
                "transaction_id": "abc123def456789ghijk",
                "block_height": 750000,
                "confirmations": 6,
                "network": "bitcoin_testnet",
                "status": "confirmed",
                "fee_satoshis": 1000
            }
        }
    )
    
    # Document reference
    document_id: str = Field(..., description="Associated document ID")
    document_hash: str = Field(..., min_length=64, max_length=64, description="Document SHA256 hash")
    metadata_hash: str = Field(..., min_length=64, max_length=64, description="Metadata JSON SHA256 hash")
    
    # Transaction details
    transaction_id: Optional[str] = Field(default=None, description="Blockchain transaction ID")
    block_height: Optional[int] = Field(default=None, ge=0, description="Block height")
    block_hash: Optional[str] = Field(default=None, description="Block hash")
    confirmations: int = Field(default=0, ge=0, description="Number of confirmations")
    
    # OpenTimestamps details
    ots_file_path: Optional[str] = Field(default=None, description="OTS file storage path")
    ots_info: Dict[str, Any] = Field(default={}, description="OpenTimestamps additional info")
    proof_type: ProofType = Field(default=ProofType.OPENTIMESTAMPS, description="Type of cryptographic proof")
    
    # Status and timestamps
    status: TransactionStatus = Field(default=TransactionStatus.PENDING, description="Transaction status")
    submitted_at: Optional[datetime] = Field(default=None, description="Submission timestamp")
    confirmed_at: Optional[datetime] = Field(default=None, description="Confirmation timestamp")
    
    # Network and fees
    network: BlockchainNetwork = Field(default=BlockchainNetwork.BITCOIN_TESTNET, description="Blockchain network")
    fee_satoshis: Optional[int] = Field(default=None, ge=0, description="Transaction fee in satoshis")
    estimated_confirmation_time: Optional[int] = Field(default=None, description="Estimated confirmation time in minutes")
    
    # Retry mechanism
    retry_count: int = Field(default=0, ge=0, le=10, description="Number of retry attempts")
    max_retries: int = Field(default=3, ge=1, le=10, description="Maximum retry attempts")
    last_error: Optional[str] = Field(default=None, max_length=1000, description="Last error message")
    next_retry_at: Optional[datetime] = Field(default=None, description="Next retry timestamp")
    
    # Additional metadata
    raw_transaction: Optional[str] = Field(default=None, description="Raw transaction hex")
    merkle_proof: Optional[Dict[str, Any]] = Field(default=None, description="Merkle proof data")
    
    # FIXED: Updated validator syntax
    @field_validator("document_hash", "metadata_hash")
    @classmethod
    def validate_hash_format(cls, v):
        """Validate SHA256 hash format"""
        import re
        if not re.match(r'^[a-fA-F0-9]{64}$', v):
            raise ValueError("Hash must be a valid SHA256 hash (64 hexadecimal characters)")
        return v.lower()
    
    # FIXED: Updated validator syntax
    @field_validator("transaction_id")
    @classmethod
    def validate_transaction_id_format(cls, v):
        """Validate transaction ID format"""
        if v is None:
            return v
        
        import re
        if not re.match(r'^[a-fA-F0-9]{64}$', v):
            raise ValueError("Transaction ID must be a valid 64-character hexadecimal string")
        return v.lower()
    
    # FIXED: Updated validator syntax
    @field_validator("block_hash")
    @classmethod
    def validate_block_hash_format(cls, v):
        """Validate block hash format"""
        if v is None:
            return v
        
        import re
        if not re.match(r'^[a-fA-F0-9]{64}$', v):
            raise ValueError("Block hash must be a valid 64-character hexadecimal string")
        return v.lower()
    
    def is_confirmed(self, min_confirmations: int = 1) -> bool:
        """Check if transaction is confirmed with minimum confirmations"""
        return self.status == TransactionStatus.CONFIRMED and self.confirmations >= min_confirmations
    
    def is_expired(self, max_age_hours: int = 24) -> bool:
        """Check if transaction is expired"""
        if not self.created_at:
            return False
        
        age = datetime.now(timezone.utc) - self.created_at
        return age.total_seconds() > (max_age_hours * 3600)
    
    def can_retry(self) -> bool:
        """Check if transaction can be retried"""
        return (
            self.status == TransactionStatus.FAILED and
            self.retry_count < self.max_retries and
            (self.next_retry_at is None or datetime.now(timezone.utc) >= self.next_retry_at)
        )


class BlockchainProof(BaseDocument):
    """Blockchain proof model"""
    
    # FIXED: Updated to use model_config
    model_config = ConfigDict(
        populate_by_name=True,
        arbitrary_types_allowed=True,
        json_schema_extra={
            "example": {
                "id": "507f1f77bcf86cd799439013",
                "transaction_id": "507f1f77bcf86cd799439011",
                "document_id": "507f1f77bcf86cd799439012",
                "proof_type": "opentimestamps",
                "proof_data": {
                    "ots_file": "path/to/proof.ots",
                    "calendar_urls": ["https://alice.btc.calendar.opentimestamps.org"]
                },
                "verification_status": "verified",
                "created_at": "2023-01-01T00:00:00Z"
            }
        }
    )
    
    transaction_id: str = Field(..., description="Associated blockchain transaction ID")
    document_id: str = Field(..., description="Associated document ID")
    proof_type: ProofType = Field(..., description="Type of cryptographic proof")
    proof_data: Dict[str, Any] = Field(..., description="Proof data and metadata")
    
    # Verification details
    verification_status: str = Field(default="pending", description="Proof verification status")
    verification_details: Dict[str, Any] = Field(default={}, description="Verification result details")
    last_verified_at: Optional[datetime] = Field(default=None, description="Last verification timestamp")
    
    # External references
    external_proof_urls: List[str] = Field(default=[], description="External proof verification URLs")
    proof_file_path: Optional[str] = Field(default=None, description="Path to proof file")
    proof_file_hash: Optional[str] = Field(default=None, description="Hash of proof file")
    
    # FIXED: Updated validator syntax
    @field_validator("verification_status")
    @classmethod
    def validate_verification_status(cls, v):
        """Validate verification status"""
        allowed_statuses = ["pending", "verified", "failed", "expired", "invalid"]
        if v not in allowed_statuses:
            raise ValueError(f"Verification status must be one of: {allowed_statuses}")
        return v
    
    # FIXED: Updated validator syntax
    @field_validator("external_proof_urls")
    @classmethod
    def validate_external_urls(cls, v):
        """Validate external proof URLs"""
        import re
        url_pattern = re.compile(
            r'^https?://'  # http:// or https://
            r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|'  # domain...
            r'localhost|'  # localhost...
            r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # ...or ip
            r'(?::\d+)?'  # optional port
            r'(?:/?|[/?]\S+)$', re.IGNORECASE)
        
        for url in v:
            if not url_pattern.match(url):
                raise ValueError(f"Invalid URL format: {url}")
        
        return v
    
    def is_verified(self) -> bool:
        """Check if proof is verified"""
        return self.verification_status == "verified"
    
    def needs_verification(self) -> bool:
        """Check if proof needs verification"""
        return self.verification_status in ["pending", "failed"]


class BlockchainHealthStatus(BaseModel):
    """Blockchain service health status"""
    
    # FIXED: Updated to use model_config
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "network": "bitcoin_testnet",
                "is_connected": True,
                "latest_block": 750000,
                "sync_status": "synced",
                "pending_transactions": 5,
                "confirmed_transactions": 1250,
                "average_confirmation_time": 15.5,
                "last_check": "2023-01-01T00:00:00Z"
            }
        }
    )
    
    network: BlockchainNetwork = Field(..., description="Blockchain network")
    is_connected: bool = Field(..., description="Connection status")
    latest_block: Optional[int] = Field(default=None, description="Latest block height")
    sync_status: str = Field(default="unknown", description="Synchronization status")
    pending_transactions: int = Field(default=0, description="Number of pending transactions")
    confirmed_transactions: int = Field(default=0, description="Number of confirmed transactions")
    failed_transactions: int = Field(default=0, description="Number of failed transactions")
    average_confirmation_time: Optional[float] = Field(default=None, description="Average confirmation time in minutes")
    fee_estimates: Dict[str, int] = Field(default={}, description="Fee estimates by priority")
    last_check: datetime = Field(default_factory=lambda: datetime.now(timezone.utc), description="Last health check")
    
    # FIXED: Updated validator syntax
    @field_validator("sync_status")
    @classmethod
    def validate_sync_status(cls, v):
        """Validate sync status"""
        allowed_statuses = ["synced", "syncing", "disconnected", "error", "unknown"]
        if v not in allowed_statuses:
            raise ValueError(f"Sync status must be one of: {allowed_statuses}")
        return v


class TransactionStatistics(BaseModel):
    """Transaction statistics model"""
    
    # FIXED: Updated to use model_config
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "total_transactions": 1500,
                "pending_count": 5,
                "confirmed_count": 1450,
                "failed_count": 45,
                "success_rate": 96.7,
                "average_confirmation_time": 15.5,
                "total_fees_paid": 15000,
                "by_network": {
                    "bitcoin_testnet": 1200,
                    "bitcoin_mainnet": 300
                },
                "by_status": {
                    "pending": 5,
                    "confirmed": 1450,
                    "failed": 45
                }
            }
        }
    )
    
    total_transactions: int = Field(default=0, description="Total number of transactions")
    pending_count: int = Field(default=0, description="Number of pending transactions")
    confirmed_count: int = Field(default=0, description="Number of confirmed transactions")
    failed_count: int = Field(default=0, description="Number of failed transactions")
    success_rate: float = Field(default=0.0, description="Success rate percentage")
    average_confirmation_time: Optional[float] = Field(default=None, description="Average confirmation time in minutes")
    median_confirmation_time: Optional[float] = Field(default=None, description="Median confirmation time in minutes")
    total_fees_paid: int = Field(default=0, description="Total fees paid in satoshis")
    average_fee: Optional[float] = Field(default=None, description="Average fee per transaction")
    by_network: Dict[str, int] = Field(default={}, description="Transaction count by network")
    by_status: Dict[str, int] = Field(default={}, description="Transaction count by status")
    by_proof_type: Dict[str, int] = Field(default={}, description="Transaction count by proof type")
    last_calculated: datetime = Field(default_factory=lambda: datetime.now(timezone.utc), description="Last calculation time")


class ProofVerificationRequest(BaseModel):
    """Proof verification request model"""
    
    # FIXED: Updated to use model_config
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "proof_id": "507f1f77bcf86cd799439013",
                "verification_type": "full",
                "include_merkle_path": True,
                "calendar_urls": ["https://alice.btc.calendar.opentimestamps.org"],
                "timeout_seconds": 30
            }
        }
    )
    
    proof_id: str = Field(..., description="Proof ID to verify")
    verification_type: str = Field(default="full", description="Type of verification to perform")
    include_merkle_path: bool = Field(default=True, description="Include Merkle path in verification")
    calendar_urls: Optional[List[str]] = Field(default=None, description="Calendar server URLs for verification")
    timeout_seconds: int = Field(default=30, ge=5, le=300, description="Verification timeout in seconds")
    force_refresh: bool = Field(default=False, description="Force refresh of cached verification results")
    
    # FIXED: Updated validator syntax
    @field_validator("verification_type")
    @classmethod
    def validate_verification_type(cls, v):
        """Validate verification type"""
        allowed_types = ["quick", "full", "deep", "audit"]
        if v not in allowed_types:
            raise ValueError(f"Verification type must be one of: {allowed_types}")
        return v


class ProofVerificationResult(BaseModel):
    """Proof verification result model"""
    
    # FIXED: Updated to use model_config
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "proof_id": "507f1f77bcf86cd799439013",
                "is_valid": True,
                "verification_timestamp": "2023-01-01T00:00:00Z",
                "blockchain_timestamp": "2023-01-01T00:00:00Z",
                "confirmations": 6,
                "verification_details": {
                    "block_height": 750000,
                    "merkle_root": "abc123...",
                    "calendar_servers_checked": 3
                },
                "verification_duration_ms": 2500,
                "warnings": [],
                "errors": []
            }
        }
    )
    
    proof_id: str = Field(..., description="Verified proof ID")
    is_valid: bool = Field(..., description="Whether proof is valid")
    verification_timestamp: datetime = Field(..., description="When verification was performed")
    blockchain_timestamp: Optional[datetime] = Field(default=None, description="Blockchain timestamp from proof")
    confirmations: Optional[int] = Field(default=None, description="Number of confirmations")
    
    verification_details: Dict[str, Any] = Field(default={}, description="Detailed verification information")
    merkle_path: Optional[List[str]] = Field(default=None, description="Merkle path if requested")
    calendar_responses: Dict[str, Any] = Field(default={}, description="Calendar server responses")
    
    verification_duration_ms: int = Field(..., ge=0, description="Verification duration in milliseconds")
    warnings: List[str] = Field(default=[], description="Verification warnings")
    errors: List[str] = Field(default=[], description="Verification errors")
    
    def has_warnings(self) -> bool:
        """Check if verification has warnings"""
        return len(self.warnings) > 0
    
    def has_errors(self) -> bool:
        """Check if verification has errors"""
        return len(self.errors) > 0
    
    def is_fully_verified(self) -> bool:
        """Check if proof is fully verified without warnings or errors"""
        return self.is_valid and not self.has_warnings() and not self.has_errors()