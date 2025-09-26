"""
Path: infrastructure/source/api/models/metadata.py
Version: 3
"""

from datetime import datetime, timezone
from typing import Optional, Dict, Any, List
from pydantic import BaseModel, Field, field_validator, ConfigDict
from enum import Enum

from .base import BaseDocument


class MetadataType(str, Enum):
    """Metadata value types"""
    STRING = "string"
    INTEGER = "integer" 
    FLOAT = "float"
    BOOLEAN = "boolean"
    DATE = "date"
    JSON = "json"


class MetadataField(BaseModel):
    """Metadata field definition"""
    
    # FIXED: Updated to use model_config
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "key": "author",
                "value": "John Doe",
                "value_type": "string",
                "is_searchable": True,
                "is_public": False
            }
        }
    )
    
    key: str = Field(..., min_length=1, max_length=100, description="Metadata key")
    value: str = Field(..., max_length=1000, description="Metadata value")
    value_type: MetadataType = Field(default=MetadataType.STRING, description="Value type")
    is_searchable: bool = Field(default=True, description="Whether field is searchable")
    is_public: bool = Field(default=False, description="Whether field is publicly visible")
    
    # FIXED: Updated validator syntax
    @field_validator("key")
    @classmethod
    def validate_key_format(cls, v):
        """Validate metadata key format"""
        import re
        
        # Check for reserved keys
        reserved_keys = ["id", "hash", "timestamp", "signature", "type", "_id", "created_at", "updated_at"]
        if v.lower() in reserved_keys:
            raise ValueError(f"Key '{v}' is reserved and cannot be used")
        
        # Check for valid characters (alphanumeric, underscore, dash)
        if not re.match(r'^[a-zA-Z0-9_-]+$', v):
            raise ValueError("Key can only contain alphanumeric characters, underscores, and dashes")
        
        return v
    
    # FIXED: Updated validator syntax
    @field_validator("value")
    @classmethod
    def validate_value_content(cls, v):
        """Validate metadata value content"""
        # Remove potential harmful content
        if any(char in v for char in ['<', '>', '&', '"', "'"]):
            raise ValueError("Value contains potentially harmful characters")
        
        return v.strip()


class MetadataSchema(BaseDocument):
    """Metadata schema definition"""
    
    # FIXED: Updated to use model_config
    model_config = ConfigDict(
        populate_by_name=True,
        arbitrary_types_allowed=True,
        json_schema_extra={
            "example": {
                "id": "507f1f77bcf86cd799439011",
                "name": "Document Schema v1",
                "description": "Standard document metadata schema",
                "fields": [
                    {
                        "key": "author",
                        "value": "John Doe",
                        "value_type": "string",
                        "is_searchable": True,
                        "is_public": False
                    }
                ],
                "is_active": True,
                "version": "1.0.0"
            }
        }
    )
    
    name: str = Field(..., min_length=1, max_length=100, description="Schema name")
    description: Optional[str] = Field(default=None, max_length=500, description="Schema description")
    fields: List[MetadataField] = Field(default=[], description="Metadata fields definition")
    is_active: bool = Field(default=True, description="Whether schema is active")
    version: str = Field(default="1.0.0", description="Schema version")
    organization_id: Optional[str] = Field(default=None, description="Organization ID")
    created_by: Optional[str] = Field(default=None, description="Creator user ID")
    
    # FIXED: Updated validator syntax
    @field_validator("fields")
    @classmethod
    def validate_fields_limit(cls, v):
        """Validate metadata fields count"""
        if len(v) > 50:
            raise ValueError("Maximum 50 metadata fields allowed per schema")
        
        # Check for duplicate keys
        keys = [field.key.lower() for field in v]
        if len(keys) != len(set(keys)):
            raise ValueError("Duplicate metadata keys are not allowed")
        
        return v
    
    # FIXED: Updated validator syntax
    @field_validator("version")
    @classmethod
    def validate_version_format(cls, v):
        """Validate version format (semantic versioning)"""
        import re
        if not re.match(r'^\d+\.\d+\.\d+$', v):
            raise ValueError("Version must follow semantic versioning (e.g., 1.0.0)")
        return v


class MetadataTemplate(BaseDocument):
    """Metadata template for quick document setup"""
    
    # FIXED: Updated to use model_config
    model_config = ConfigDict(
        populate_by_name=True,
        arbitrary_types_allowed=True,
        json_schema_extra={
            "example": {
                "id": "507f1f77bcf86cd799439012",
                "name": "Legal Document Template",
                "description": "Template for legal documents",
                "category": "legal",
                "metadata_defaults": {
                    "department": "legal",
                    "confidentiality": "internal"
                },
                "required_fields": ["contract_type", "parties"],
                "is_public": False
            }
        }
    )
    
    name: str = Field(..., min_length=1, max_length=100, description="Template name")
    description: Optional[str] = Field(default=None, max_length=500, description="Template description")
    category: Optional[str] = Field(default=None, max_length=50, description="Template category")
    metadata_defaults: Dict[str, str] = Field(default={}, description="Default metadata values")
    required_fields: List[str] = Field(default=[], description="Required metadata fields")
    optional_fields: List[str] = Field(default=[], description="Optional metadata fields")
    is_public: bool = Field(default=False, description="Whether template is publicly available")
    organization_id: Optional[str] = Field(default=None, description="Organization ID")
    created_by: Optional[str] = Field(default=None, description="Creator user ID")
    usage_count: int = Field(default=0, description="Number of times template was used")
    
    # FIXED: Updated validator syntax
    @field_validator("metadata_defaults")
    @classmethod
    def validate_metadata_defaults(cls, v):
        """Validate default metadata"""
        if len(v) > 20:
            raise ValueError("Maximum 20 default metadata fields allowed")
        
        for key, value in v.items():
            if len(key) > 100 or len(str(value)) > 1000:
                raise ValueError("Metadata key or value too long")
        
        return v
    
    # FIXED: Updated validator syntax
    @field_validator("required_fields", "optional_fields")
    @classmethod
    def validate_field_lists(cls, v):
        """Validate field lists"""
        if len(v) > 30:
            raise ValueError("Maximum 30 fields allowed in list")
        
        for field in v:
            if len(field) > 100:
                raise ValueError("Field name too long")
        
        return v


class DocumentMetadata(BaseModel):
    """Document metadata instance"""
    
    # FIXED: Updated to use model_config
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "document_id": "507f1f77bcf86cd799439013",
                "schema_id": "507f1f77bcf86cd799439011",
                "template_id": "507f1f77bcf86cd799439012",
                "metadata": {
                    "author": "John Doe",
                    "department": "legal",
                    "contract_type": "service_agreement"
                },
                "validation_status": "valid",
                "last_validated": "2023-01-01T00:00:00Z"
            }
        }
    )
    
    document_id: str = Field(..., description="Associated document ID")
    schema_id: Optional[str] = Field(default=None, description="Metadata schema ID")
    template_id: Optional[str] = Field(default=None, description="Template ID used")
    metadata: Dict[str, str] = Field(..., description="Document metadata key-value pairs")
    validation_status: str = Field(default="pending", description="Validation status")
    validation_errors: List[str] = Field(default=[], description="Validation error messages")
    last_validated: Optional[datetime] = Field(default=None, description="Last validation timestamp")
    
    # FIXED: Updated validator syntax
    @field_validator("metadata")
    @classmethod
    def validate_metadata_content(cls, v):
        """Validate metadata content and size"""
        if len(v) > 50:
            raise ValueError("Maximum 50 metadata fields allowed")
        
        total_size = sum(len(str(k)) + len(str(val)) for k, val in v.items())
        if total_size > 10240:  # 10KB
            raise ValueError("Metadata total size cannot exceed 10KB")
        
        # Validate individual fields
        for key, value in v.items():
            if len(key) > 100:
                raise ValueError(f"Metadata key '{key}' exceeds 100 characters")
            
            if len(str(value)) > 1000:
                raise ValueError(f"Metadata value for '{key}' exceeds 1000 characters")
            
            # Check for potentially harmful content
            if any(char in str(value) for char in ['<', '>', '&', '"', "'"]):
                raise ValueError(f"Metadata value for '{key}' contains potentially harmful characters")
        
        return v
    
    # FIXED: Updated validator syntax
    @field_validator("validation_status")
    @classmethod
    def validate_status_value(cls, v):
        """Validate validation status"""
        allowed_statuses = ["pending", "valid", "invalid", "warning"]
        if v not in allowed_statuses:
            raise ValueError(f"Status must be one of: {allowed_statuses}")
        return v


class MetadataSearchQuery(BaseModel):
    """Metadata search query model"""
    
    # FIXED: Updated to use model_config
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "filters": {
                    "author": "John Doe",
                    "department": "legal"
                },
                "search_text": "contract agreement",
                "date_range": {
                    "start": "2023-01-01T00:00:00Z",
                    "end": "2023-12-31T23:59:59Z"
                },
                "include_private": False
            }
        }
    )
    
    filters: Dict[str, str] = Field(default={}, description="Metadata filters")
    search_text: Optional[str] = Field(default=None, max_length=200, description="Free text search")
    date_range: Optional[Dict[str, datetime]] = Field(default=None, description="Date range filter")
    include_private: bool = Field(default=False, description="Include private metadata fields")
    schema_id: Optional[str] = Field(default=None, description="Filter by schema ID")
    organization_id: Optional[str] = Field(default=None, description="Filter by organization")
    
    # FIXED: Updated validator syntax
    @field_validator("filters")
    @classmethod
    def validate_filters_size(cls, v):
        """Validate filters size"""
        if len(v) > 20:
            raise ValueError("Maximum 20 metadata filters allowed")
        
        for key, value in v.items():
            if len(key) > 100 or len(str(value)) > 500:
                raise ValueError("Filter key or value too long")
        
        return v
    
    # FIXED: Updated validator syntax
    @field_validator("date_range")
    @classmethod
    def validate_date_range(cls, v):
        """Validate date range"""
        if v and "start" in v and "end" in v:
            if v["start"] >= v["end"]:
                raise ValueError("Start date must be before end date")
        return v


class MetadataStatistics(BaseModel):
    """Metadata usage statistics"""
    
    # FIXED: Updated to use model_config
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "total_schemas": 5,
                "total_templates": 12,
                "total_metadata_fields": 150,
                "most_used_fields": [
                    {"key": "author", "count": 1250},
                    {"key": "department", "count": 980}
                ],
                "schema_usage": {
                    "507f1f77bcf86cd799439011": 340,
                    "507f1f77bcf86cd799439012": 210
                },
                "template_usage": {
                    "507f1f77bcf86cd799439013": 150,
                    "507f1f77bcf86cd799439014": 95
                }
            }
        }
    )
    
    total_schemas: int = Field(default=0, description="Total number of schemas")
    total_templates: int = Field(default=0, description="Total number of templates")
    total_metadata_fields: int = Field(default=0, description="Total metadata fields defined")
    most_used_fields: List[Dict[str, Any]] = Field(default=[], description="Most frequently used fields")
    schema_usage: Dict[str, int] = Field(default={}, description="Schema usage counts")
    template_usage: Dict[str, int] = Field(default={}, description="Template usage counts")
    field_type_distribution: Dict[str, int] = Field(default={}, description="Distribution of field types")
    validation_success_rate: float = Field(default=0.0, description="Metadata validation success rate")
    last_calculated: datetime = Field(default_factory=lambda: datetime.now(timezone.utc), description="Last calculation time")


class MetadataValidationRule(BaseModel):
    """Metadata validation rule"""
    
    # FIXED: Updated to use model_config
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "field_name": "email",
                "rule_type": "regex",
                "rule_value": "^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$",
                "error_message": "Must be a valid email address",
                "is_required": True,
                "severity": "error"
            }
        }
    )
    
    field_name: str = Field(..., description="Metadata field name")
    rule_type: str = Field(..., description="Validation rule type (regex, range, enum, etc.)")
    rule_value: str = Field(..., description="Rule value/pattern")
    error_message: str = Field(..., description="Error message for validation failure")
    is_required: bool = Field(default=False, description="Whether field is required")
    severity: str = Field(default="error", description="Validation severity level")
    
    # FIXED: Updated validator syntax
    @field_validator("rule_type")
    @classmethod
    def validate_rule_type(cls, v):
        """Validate rule type"""
        allowed_types = ["regex", "range", "enum", "length", "format", "custom"]
        if v not in allowed_types:
            raise ValueError(f"Rule type must be one of: {allowed_types}")
        return v
    
    # FIXED: Updated validator syntax
    @field_validator("severity")
    @classmethod
    def validate_severity(cls, v):
        """Validate severity level"""
        allowed_severities = ["error", "warning", "info"]
        if v not in allowed_severities:
            raise ValueError(f"Severity must be one of: {allowed_severities}")
        return v