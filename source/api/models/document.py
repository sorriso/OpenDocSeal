"""
Path: infrastructure/source/api/models/document.py
Version: 2
"""

from datetime import datetime, timezone
from typing import Optional, Dict, Any, List
from pydantic import BaseModel, Field, field_validator, ConfigDict
from enum import Enum

from .base import BaseDocument, HashModel, FileInfoModel, DocumentStatus


class DocumentCreate(BaseModel):
    """Document creation model"""
    
    # FIXED: Updated to use model_config
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "name": "contract.pdf",
                "description": "Important contract document",
                "hash": "a1b2c3d4e5f6789012345678901234567890123456789012345678901234567890",
                "size": 1024000,
                "file_type": "application/pdf",
                "metadata": {
                    "department": "legal",
                    "contract_type": "service_agreement"
                },
                "upload_file": True
            }
        }
    )
    
    name: str = Field(..., min_length=1, max_length=255, description="Document name")
    description: Optional[str] = Field(default=None, max_length=1000, description="Document description")
    hash: str = Field(..., min_length=64, max_length=64, description="SHA256 hash of the document")
    size: int = Field(..., ge=1, description="Document size in bytes")
    file_type: str = Field(..., description="Document MIME type")
    metadata: Dict[str, str] = Field(default={}, description="Document metadata")
    upload_file: bool = Field(default=True, description="Whether to store the file")
    
    # FIXED: Updated validator syntax
    @field_validator("hash")
    @classmethod
    def validate_hash_format(cls, v):
        """Validate SHA256 hash format"""
        import re
        if not re.match(r'^[a-fA-F0-9]{64}$', v):
            raise ValueError("Hash must be a valid SHA256 hash (64 hexadecimal characters)")
        return v.lower()
    
    # FIXED: Updated validator syntax
    @field_validator("metadata")
    @classmethod
    def validate_metadata_size(cls, v):
        """Validate metadata size and keys"""
        if len(v) > 50:
            raise ValueError("Maximum 50 metadata keys allowed")
        
        total_size = sum(len(str(k)) + len(str(val)) for k, val in v.items())
        if total_size > 10240:  # 10KB
            raise ValueError("Metadata total size cannot exceed 10KB")
        
        # Validate keys
        reserved_keys = ["id", "hash", "timestamp", "signature", "type", "_id"]
        for key in v.keys():
            if key.lower() in reserved_keys:
                raise ValueError(f"Key '{key}' is reserved and cannot be used")
            
            if len(key) > 100:
                raise ValueError(f"Key '{key}' exceeds maximum length of 100 characters")
            
            if len(str(v[key])) > 1000:
                raise ValueError(f"Value for key '{key}' exceeds maximum length of 1000 characters")
        
        return v
    
    # FIXED: Updated validator syntax
    @field_validator("file_type")
    @classmethod
    def validate_file_type(cls, v):
        """Validate MIME type format"""
        import re
        if not re.match(r'^[a-zA-Z0-9][a-zA-Z0-9!#$&\-\^_]*\/[a-zA-Z0-9][a-zA-Z0-9!#$&\-\^_.]*$', v):
            raise ValueError("Invalid MIME type format")
        return v.lower()


class DocumentUpdate(BaseModel):
    """Document update model"""
    
    # FIXED: Updated to use model_config
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "name": "updated_contract.pdf",
                "description": "Updated contract document",
                "metadata": {
                    "department": "legal",
                    "status": "reviewed"
                }
            }
        }
    )
    
    name: Optional[str] = Field(default=None, min_length=1, max_length=255, description="Document name")
    description: Optional[str] = Field(default=None, max_length=1000, description="Document description")
    metadata: Optional[Dict[str, str]] = Field(default=None, description="Document metadata")
    
    # FIXED: Updated validator syntax
    @field_validator("metadata")
    @classmethod
    def validate_metadata_size(cls, v):
        """Validate metadata size and keys"""
        if v is None:
            return v
            
        if len(v) > 50:
            raise ValueError("Maximum 50 metadata keys allowed")
        
        total_size = sum(len(str(k)) + len(str(val)) for k, val in v.items())
        if total_size > 10240:  # 10KB
            raise ValueError("Metadata total size cannot exceed 10KB")
        
        # Validate keys
        reserved_keys = ["id", "hash", "timestamp", "signature", "type", "_id"]
        for key in v.keys():
            if key.lower() in reserved_keys:
                raise ValueError(f"Key '{key}' is reserved and cannot be used")
            
            if len(key) > 100:
                raise ValueError(f"Key '{key}' exceeds maximum length of 100 characters")
            
            if len(str(v[key])) > 1000:
                raise ValueError(f"Value for key '{key}' exceeds maximum length of 1000 characters")
        
        return v


class Document(BaseDocument):
    """Document model"""
    
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
                "user_id": "507f1f77bcf86cd799439012",
                "name": "contract.pdf",
                "description": "Important contract",
                "hash": "a1b2c3d4...",
                "size": 1024000,
                "file_type": "application/pdf",
                "status": "completed",
                "storage_path": "/documents/abc123.pdf",
                "blockchain_transaction_id": "tx_789012",
                "proof_package_path": "/proofs/abc123.zip",
                "metadata": {"department": "legal"},
                "created_at": "2023-01-01T00:00:00Z"
            }
        }
    )
    
    user_id: str = Field(..., description="Document owner user ID")
    name: str = Field(..., min_length=1, max_length=255, description="Document name")
    description: Optional[str] = Field(default=None, max_length=1000, description="Document description")
    hash: str = Field(..., min_length=64, max_length=64, description="SHA256 hash of the document")
    size: int = Field(..., ge=1, description="Document size in bytes")
    file_type: str = Field(..., description="Document MIME type")
    status: DocumentStatus = Field(default=DocumentStatus.DRAFT, description="Document processing status")
    
    # Storage information
    storage_path: Optional[str] = Field(default=None, description="Path in object storage")
    storage_bucket: Optional[str] = Field(default=None, description="Storage bucket name")
    
    # Blockchain information
    blockchain_transaction_id: Optional[str] = Field(default=None, description="Blockchain transaction ID")
    blockchain_hash: Optional[str] = Field(default=None, description="Hash submitted to blockchain")
    blockchain_timestamp: Optional[datetime] = Field(default=None, description="Blockchain timestamp")
    blockchain_proof: Optional[Dict[str, Any]] = Field(default=None, description="Blockchain proof data")
    
    # Proof package information
    proof_package_path: Optional[str] = Field(default=None, description="Path to proof package")
    proof_package_hash: Optional[str] = Field(default=None, description="Hash of proof package")
    
    # Metadata
    metadata: Dict[str, str] = Field(default={}, description="Document metadata")
    tags: List[str] = Field(default=[], description="Document tags")
    
    # Processing information
    processing_started_at: Optional[datetime] = Field(default=None, description="Processing start time")
    processing_completed_at: Optional[datetime] = Field(default=None, description="Processing completion time")
    error_message: Optional[str] = Field(default=None, description="Error message if processing failed")
    retry_count: int = Field(default=0, description="Number of retry attempts")
    
    # FIXED: Updated validator syntax
    @field_validator("hash")
    @classmethod
    def validate_hash_format(cls, v):
        """Validate SHA256 hash format"""
        import re
        if not re.match(r'^[a-fA-F0-9]{64}$', v):
            raise ValueError("Hash must be a valid SHA256 hash (64 hexadecimal characters)")
        return v.lower()
    
    # FIXED: Updated validator syntax
    @field_validator("metadata")
    @classmethod
    def validate_metadata_size(cls, v):
        """Validate metadata size and keys"""
        if len(v) > 50:
            raise ValueError("Maximum 50 metadata keys allowed")
        
        total_size = sum(len(str(k)) + len(str(val)) for k, val in v.items())
        if total_size > 10240:  # 10KB
            raise ValueError("Metadata total size cannot exceed 10KB")
        
        return v
    
    def is_processing_complete(self) -> bool:
        """Check if document processing is complete"""
        return self.status in [DocumentStatus.COMPLETED, DocumentStatus.ERROR]
    
    def is_blockchain_confirmed(self) -> bool:
        """Check if blockchain transaction is confirmed"""
        return self.blockchain_transaction_id is not None and self.blockchain_timestamp is not None
    
    def get_processing_duration(self) -> Optional[float]:
        """Get processing duration in seconds"""
        if self.processing_started_at and self.processing_completed_at:
            return (self.processing_completed_at - self.processing_started_at).total_seconds()
        return None


class DocumentResponse(BaseModel):
    """Document response model"""
    
    # FIXED: Updated to use model_config
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "id": "507f1f77bcf86cd799439011",
                "name": "contract.pdf",
                "description": "Important contract",
                "hash": "a1b2c3d4...",
                "size": 1024000,
                "file_type": "application/pdf",
                "status": "completed",
                "blockchain_transaction_id": "tx_789012",
                "metadata": {"department": "legal"},
                "created_at": "2023-01-01T00:00:00Z",
                "processing_completed_at": "2023-01-01T00:05:00Z"
            }
        }
    )
    
    id: str = Field(..., description="Document ID")
    name: str = Field(..., description="Document name")
    description: Optional[str] = Field(default=None, description="Document description")
    hash: str = Field(..., description="SHA256 hash")
    size: int = Field(..., description="Document size in bytes")
    file_type: str = Field(..., description="Document MIME type")
    status: DocumentStatus = Field(..., description="Processing status")
    blockchain_transaction_id: Optional[str] = Field(default=None, description="Blockchain transaction ID")
    blockchain_timestamp: Optional[datetime] = Field(default=None, description="Blockchain timestamp")
    metadata: Dict[str, str] = Field(default={}, description="Document metadata")
    tags: List[str] = Field(default=[], description="Document tags")
    created_at: datetime = Field(..., description="Creation timestamp")
    processing_completed_at: Optional[datetime] = Field(default=None, description="Processing completion time")
    proof_package_available: bool = Field(default=False, description="Proof package availability")


class DocumentSearchFilter(BaseModel):
    """Document search filter model"""
    
    # FIXED: Updated to use model_config
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "name": "contract",
                "file_type": "application/pdf",
                "status": "completed",
                "metadata": {"department": "legal"},
                "tags": ["important"],
                "created_after": "2023-01-01T00:00:00Z",
                "created_before": "2023-12-31T23:59:59Z"
            }
        }
    )
    
    name: Optional[str] = Field(default=None, description="Document name search")
    file_type: Optional[str] = Field(default=None, description="Document MIME type filter")
    status: Optional[DocumentStatus] = Field(default=None, description="Document status filter")
    metadata: Optional[Dict[str, str]] = Field(default=None, description="Metadata filters")
    tags: Optional[List[str]] = Field(default=None, description="Tag filters")
    created_after: Optional[datetime] = Field(default=None, description="Created after date")
    created_before: Optional[datetime] = Field(default=None, description="Created before date")
    min_size: Optional[int] = Field(default=None, ge=0, description="Minimum file size")
    max_size: Optional[int] = Field(default=None, ge=0, description="Maximum file size")


class DocumentStatistics(BaseModel):
    """Document statistics model"""
    
    # FIXED: Updated to use model_config
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "total_documents": 150,
                "completed_documents": 145,
                "processing_documents": 3,
                "error_documents": 2,
                "total_size_bytes": 1073741824,
                "average_processing_time": 45.5,
                "documents_by_type": {
                    "application/pdf": 100,
                    "image/jpeg": 30,
                    "text/plain": 20
                },
                "documents_this_month": 25
            }
        }
    )
    
    total_documents: int = Field(default=0, description="Total number of documents")
    completed_documents: int = Field(default=0, description="Number of completed documents")
    processing_documents: int = Field(default=0, description="Number of processing documents")
    error_documents: int = Field(default=0, description="Number of failed documents")
    total_size_bytes: int = Field(default=0, description="Total storage used in bytes")
    average_processing_time: Optional[float] = Field(default=None, description="Average processing time in seconds")
    documents_by_type: Dict[str, int] = Field(default={}, description="Document count by MIME type")
    documents_this_month: int = Field(default=0, description="Documents created this month")
    blockchain_confirmed: int = Field(default=0, description="Documents with blockchain confirmation")


class ProofPackageInfo(BaseModel):
    """Proof package information model"""
    
    # FIXED: Updated to use model_config
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "document_id": "507f1f77bcf86cd799439011",
                "package_hash": "b2c3d4e5f6...",
                "package_size": 2048000,
                "created_at": "2023-01-01T00:05:00Z",
                "download_url": "https://api.example.com/documents/507f1f77bcf86cd799439011/proof",
                "expires_at": "2023-01-01T00:10:00Z",
                "blockchain_included": True,
                "verification_instructions": "Instructions for verification"
            }
        }
    )
    
    document_id: str = Field(..., description="Document ID")
    package_hash: str = Field(..., description="Proof package hash")
    package_size: int = Field(..., description="Proof package size in bytes")
    created_at: datetime = Field(..., description="Package creation time")
    download_url: str = Field(..., description="Temporary download URL")
    expires_at: datetime = Field(..., description="Download URL expiration")
    blockchain_included: bool = Field(default=True, description="Blockchain proof included")
    verification_instructions: Optional[str] = Field(default=None, description="Verification instructions")