"""
Path: infrastructure/source/api/routes/documents.py
Version: 6 - INTERFACE SIGNATURE FIXES
"""

import logging
from typing import List, Optional, Dict, Any
from datetime import datetime, timezone
import json

from fastapi import APIRouter, Depends, HTTPException, status, Request, UploadFile, File, Query, Form
from fastapi.responses import RedirectResponse

from ..models.document import (
    DocumentCreate, DocumentUpdate, DocumentResponse, DocumentSearchQuery,
    DocumentUploadResponse, DocumentDownloadResponse, DocumentVerificationRequest,
    DocumentVerificationResponse, DocumentStatistics, BulkDocumentOperation,
    BulkOperationResponse
)
from ..models.blockchain import BlockchainProofResponse
from ..models.base import ResponseModel, PaginatedResponse
from ..services.interfaces import DocumentServiceInterface, BlockchainServiceInterface
from ..dependencies import (
    get_document_service, get_blockchain_service,
    get_current_active_user, get_admin_user, get_correlation_id,
    require_documents_read, require_documents_write, require_documents_delete,
    get_file_validator  # NEW: File security dependency
)
from ..database import log_audit_event
from ..config import get_settings
from ..utils.file_security import validate_file_upload  # NEW: Import file security
from ..utils.security import secure_filename, hash_file_content  # NEW: Security utilities

logger = logging.getLogger(__name__)
settings = get_settings()

router = APIRouter()


# NEW: Secure File Upload Endpoint
@router.post(
    "/upload",
    response_model=DocumentUploadResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Secure file upload",
    description="Upload file with comprehensive security validation (MIME, malware, size checks)",
    responses={
        201: {"description": "File uploaded and document created successfully"},
        400: {"description": "File validation failed or malicious content detected"},
        413: {"description": "File too large"},
        401: {"description": "Authentication required"},
        415: {"description": "Unsupported file type"}
    }
)
async def upload_file_secure(
    file: UploadFile = File(..., description="File to upload"),
    metadata: Optional[str] = Form(None, description="JSON metadata for document"),
    request: Request = None,
    current_user = Depends(get_current_active_user),
    document_service: DocumentServiceInterface = Depends(get_document_service),
    correlation_id: str = Depends(get_correlation_id)
) -> DocumentUploadResponse:
    """Secure file upload with comprehensive validation"""
    
    try:
        # Step 1: Comprehensive file security validation
        logger.info(f"Starting secure file upload: {file.filename}")
        validation_result = await validate_file_upload(file)
        
        if not validation_result['valid']:
            logger.warning(
                f"File upload validation failed: {file.filename}",
                extra={
                    "correlation_id": correlation_id,
                    "user_id": str(current_user.id),
                    "threats": validation_result.get('threats', []),
                    "filename": file.filename
                }
            )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"File validation failed: {'; '.join(validation_result.get('threats', ['Unknown error']))}"
            )
        
        # Step 2: Read file content for document creation
        content = await file.read()
        file_size = len(content)
        file_hash = validation_result['hash']
        detected_mime = validation_result['detected_mime']
        secure_name = secure_filename(file.filename or "uploaded_file")
        
        # Reset file position
        await file.seek(0)
        
        # Step 3: Parse metadata if provided
        document_metadata = {}
        if metadata:
            try:
                document_metadata = json.loads(metadata)
            except json.JSONDecodeError:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Invalid JSON metadata"
                )
        
        # Step 4: Create DocumentCreate object
        document_data = DocumentCreate(
            name=secure_name,
            hash=file_hash,
            size=file_size,
            file_type=detected_mime,
            metadata=document_metadata
        )
        
        # Step 5: FIXED - Use correct interface signature
        document_response = await document_service.create_document(
            user_id=str(current_user.id),
            document_data=document_data,
            file_content=file
        )
        
        # Log successful upload
        await log_audit_event(
            action="secure_file_uploaded",
            user_id=str(current_user.id),
            details={
                "filename": secure_name,
                "original_filename": file.filename,
                "file_size": file_size,
                "detected_mime": detected_mime
            }
        )
        
        return document_response
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(
            f"Secure file upload failed: {e}",
            extra={
                "correlation_id": correlation_id,
                "user_id": str(current_user.id),
                "filename": file.filename if file else "unknown"
            },
            exc_info=True
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Secure file upload failed"
        )


# Document CRUD endpoints (EXISTING - updated for consistency)
@router.post(
    "/",
    response_model=DocumentUploadResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create document",
    description="Create a new document record and optionally get upload URL",
    responses={
        201: {"description": "Document created successfully"},
        400: {"description": "Validation error or duplicate document"},
        401: {"description": "Authentication required"},
        413: {"description": "File too large"}
    }
)
async def create_document(
    document_data: DocumentCreate,
    request: Request,
    current_user=Depends(get_current_active_user),
    document_service: DocumentServiceInterface = Depends(get_document_service),
    correlation_id: str = Depends(get_correlation_id)
) -> DocumentUploadResponse:
    """Create a new document record"""
    
    try:
        # Check file size limit
        if document_data.size > settings.max_file_size:
            raise HTTPException(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                detail=f"File too large. Maximum size is {settings.max_file_size} bytes"
            )
        
        # Check file type
        if document_data.file_type not in settings.allowed_file_types:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"File type '{document_data.file_type}' not allowed"
            )
        
        # FIXED: Use correct interface signature
        document_response = await document_service.create_document(
            user_id=str(current_user.id),
            document_data=document_data,
            file_content=None  # No file content for metadata-only creation
        )
        
        logger.info(
            f"Document created: {document_response.id}",
            extra={
                "correlation_id": correlation_id,
                "user_id": str(current_user.id),
                "document_id": document_response.id
            }
        )
        
        return document_response
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(
            f"Error creating document: {e}",
            extra={
                "correlation_id": correlation_id,
                "user_id": str(current_user.id)
            }
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create document"
        )


@router.get(
    "/",
    response_model=PaginatedResponse[DocumentResponse],
    summary="List documents",
    description="Get paginated list of user documents with optional search and filters",
    responses={
        200: {"description": "Documents retrieved successfully"},
        401: {"description": "Authentication required"}
    }
)
async def list_documents(
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(20, ge=1, le=100, description="Items per page"),
    query: Optional[str] = Query(None, description="Search query"),
    status_filter: Optional[str] = Query(None, description="Status filter"),
    date_from: Optional[datetime] = Query(None, description="Date from filter"),
    date_to: Optional[datetime] = Query(None, description="Date to filter"),
    current_user = Depends(get_current_active_user),
    document_service: DocumentServiceInterface = Depends(get_document_service),
    correlation_id: str = Depends(get_correlation_id)
) -> PaginatedResponse[DocumentResponse]:
    """Get paginated list of user documents"""
    
    try:
        # Build search query
        search_query = DocumentSearchQuery(
            page=page,
            page_size=page_size,
            query=query,
            status=status_filter,
            created_after=date_from,
            created_before=date_to
        )
        
        # Get documents using the correct interface
        documents, total_count = await document_service.search_documents(
            user_id=str(current_user.id),
            query=search_query
        )
        
        # Calculate pagination info
        total_pages = (total_count + page_size - 1) // page_size
        
        logger.debug(
            f"Documents listed: {len(documents)} of {total_count}",
            extra={
                "correlation_id": correlation_id,
                "user_id": str(current_user.id),
                "page": page,
                "page_size": page_size
            }
        )
        
        return PaginatedResponse(
            items=documents,
            total=total_count,
            page=page,
            page_size=page_size,
            total_pages=total_pages
        )
        
    except Exception as e:
        logger.error(
            f"Error listing documents: {e}",
            extra={
                "correlation_id": correlation_id,
                "user_id": str(current_user.id)
            }
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve documents"
        )


@router.get(
    "/{document_id}",
    response_model=DocumentResponse,
    summary="Get document",
    description="Get document details by ID",
    responses={
        200: {"description": "Document retrieved successfully"},
        401: {"description": "Authentication required"},
        404: {"description": "Document not found"}
    }
)
async def get_document(
    document_id: str,
    current_user = Depends(get_current_active_user),
    document_service: DocumentServiceInterface = Depends(get_document_service),
    correlation_id: str = Depends(get_correlation_id)
) -> DocumentResponse:
    """Get document by ID"""
    
    try:
        document = await document_service.get_document(document_id, str(current_user.id))
        
        if not document:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Document not found"
            )
        
        logger.debug(
            f"Document retrieved: {document_id}",
            extra={
                "correlation_id": correlation_id,
                "user_id": str(current_user.id),
                "document_id": document_id
            }
        )
        
        return document
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(
            f"Error retrieving document: {e}",
            extra={
                "correlation_id": correlation_id,
                "user_id": str(current_user.id),
                "document_id": document_id
            }
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve document"
        )


@router.put(
    "/{document_id}",
    response_model=DocumentResponse,
    summary="Update document",
    description="Update document metadata",
    responses={
        200: {"description": "Document updated successfully"},
        401: {"description": "Authentication required"},
        404: {"description": "Document not found"}
    }
)
async def update_document(
    document_id: str,
    document_update: DocumentUpdate,
    request: Request,
    current_user = Depends(get_current_active_user),
    document_service: DocumentServiceInterface = Depends(get_document_service),
    correlation_id: str = Depends(get_correlation_id)
) -> DocumentResponse:
    """Update document metadata"""
    
    try:
        updated_document = await document_service.update_document(
            document_id, str(current_user.id), document_update
        )
        
        if not updated_document:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Document not found"
            )
        
        # Log document update
        await log_audit_event(
            action="document_updated",
            user_id=str(current_user.id),
            details={
                "document_id": document_id,
                "fields_updated": list(document_update.model_dump(exclude_unset=True).keys())
            },
            ip_address=request.client.host,
            correlation_id=correlation_id
        )
        
        logger.info(
            f"Document updated: {document_id}",
            extra={
                "correlation_id": correlation_id,
                "user_id": str(current_user.id),
                "document_id": document_id
            }
        )
        
        return updated_document
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(
            f"Error updating document: {e}",
            extra={
                "correlation_id": correlation_id,
                "user_id": str(current_user.id),
                "document_id": document_id
            }
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update document"
        )


@router.delete(
    "/{document_id}",
    response_model=ResponseModel,
    summary="Delete document",
    description="Delete document and associated files",
    responses={
        200: {"description": "Document deleted successfully"},
        401: {"description": "Authentication required"},
        404: {"description": "Document not found"}
    }
)
async def delete_document(
    document_id: str,
    request: Request,
    current_user = Depends(get_current_active_user),
    document_service: DocumentServiceInterface = Depends(get_document_service),
    correlation_id: str = Depends(get_correlation_id)
) -> ResponseModel:
    """Delete document"""
    
    try:
        success = await document_service.delete_document(document_id, str(current_user.id))
        
        if not success:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Document not found"
            )
        
        # Log document deletion
        await log_audit_event(
            action="document_deleted",
            user_id=str(current_user.id),
            details={"document_id": document_id},
            ip_address=request.client.host,
            correlation_id=correlation_id
        )
        
        logger.info(
            f"Document deleted: {document_id}",
            extra={
                "correlation_id": correlation_id,
                "user_id": str(current_user.id),
                "document_id": document_id
            }
        )
        
        return ResponseModel(
            success=True,
            message="Document deleted successfully"
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(
            f"Error deleting document: {e}",
            extra={
                "correlation_id": correlation_id,
                "user_id": str(current_user.id),
                "document_id": document_id
            }
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to delete document"
        )


# Document download and proof endpoints
@router.get(
    "/{document_id}/download",
    response_model=DocumentDownloadResponse,
    summary="Download document",
    description="Download document proof package",
    responses={
        200: {"description": "Download URL generated successfully"},
        302: {"description": "Redirect to download URL"},
        401: {"description": "Authentication required"},
        404: {"description": "Document not found"}
    }
)
async def download_document(
    document_id: str,
    current_user = Depends(get_current_active_user),
    document_service: DocumentServiceInterface = Depends(get_document_service),
    correlation_id: str = Depends(get_correlation_id)
) -> DocumentDownloadResponse:
    """Download document proof package"""
    
    try:
        download_response = await document_service.download_document(
            document_id, str(current_user.id)
        )
        
        if not download_response:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Document not found or not ready for download"
            )
        
        # Log download request
        await log_audit_event(
            action="document_download_requested",
            user_id=str(current_user.id),
            details={"document_id": document_id},
            correlation_id=correlation_id
        )
        
        logger.info(
            f"Document download requested: {document_id}",
            extra={
                "correlation_id": correlation_id,
                "user_id": str(current_user.id),
                "document_id": document_id
            }
        )
        
        return download_response
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(
            f"Error downloading document: {e}",
            extra={
                "correlation_id": correlation_id,
                "user_id": str(current_user.id),
                "document_id": document_id
            }
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to generate download"
        )


@router.get(
    "/{document_id}/proof",
    response_model=BlockchainProofResponse,
    summary="Get blockchain proof",
    description="Get blockchain proof for document",
    responses={
        200: {"description": "Proof retrieved successfully"},
        401: {"description": "Authentication required"},
        404: {"description": "Document or proof not found"}
    }
)
async def get_document_proof(
    document_id: str,
    current_user = Depends(get_current_active_user),
    document_service: DocumentServiceInterface = Depends(get_document_service),
    blockchain_service: BlockchainServiceInterface = Depends(get_blockchain_service),
    correlation_id: str = Depends(get_correlation_id)
) -> BlockchainProofResponse:
    """Get blockchain proof for document"""
    
    try:
        # Get document to find blockchain transaction ID
        document = await document_service.get_document(document_id, str(current_user.id))
        
        if not document:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Document not found"
            )
        
        if not document.blockchain_transaction_id:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Blockchain proof not available for this document"
            )
        
        # Get blockchain proof
        proof_response = await blockchain_service.get_proof(
            document.blockchain_transaction_id, str(current_user.id)
        )
        
        if not proof_response:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Blockchain proof not found"
            )
        
        logger.debug(
            f"Blockchain proof retrieved: {document_id}",
            extra={
                "correlation_id": correlation_id,
                "user_id": str(current_user.id),
                "document_id": document_id,
                "transaction_id": document.blockchain_transaction_id
            }
        )
        
        return proof_response
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(
            f"Error retrieving blockchain proof: {e}",
            extra={
                "correlation_id": correlation_id,
                "user_id": str(current_user.id),
                "document_id": document_id
            }
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve blockchain proof"
        )


# Document verification endpoint
@router.post(
    "/verify",
    response_model=DocumentVerificationResponse,
    summary="Verify document",
    description="Verify document authenticity and integrity using hash",
    responses={
        200: {"description": "Verification completed"},
        400: {"description": "Invalid verification request"}
    }
)
async def verify_document(
    verification_request: DocumentVerificationRequest,
    document_service: DocumentServiceInterface = Depends(get_document_service),
    correlation_id: str = Depends(get_correlation_id)
) -> DocumentVerificationResponse:
    """Verify document authenticity"""
    
    try:
        verification_response = await document_service.verify_document(verification_request)
        
        logger.info(
            f"Document verification requested for hash: {verification_request.hash[:16]}...",
            extra={
                "correlation_id": correlation_id,
                "verification_result": verification_response.is_valid
            }
        )
        
        return verification_response
        
    except Exception as e:
        logger.error(
            f"Error verifying document: {e}",
            extra={"correlation_id": correlation_id}
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Document verification failed"
        )


# User statistics endpoint
@router.get(
    "/statistics",
    response_model=DocumentStatistics,
    summary="Get user document statistics",
    description="Get statistics about user documents",
    responses={
        200: {"description": "Statistics retrieved successfully"},
        401: {"description": "Authentication required"}
    }
)
async def get_user_document_statistics(
    current_user = Depends(get_current_active_user),
    document_service: DocumentServiceInterface = Depends(get_document_service),
    correlation_id: str = Depends(get_correlation_id)
) -> DocumentStatistics:
    """Get user document statistics"""
    
    try:
        statistics = await document_service.get_user_statistics(str(current_user.id))
        
        logger.debug(
            f"Document statistics retrieved for user: {current_user.email}",
            extra={
                "correlation_id": correlation_id,
                "user_id": str(current_user.id),
                "total_documents": statistics.total_documents
            }
        )
        
        return statistics
        
    except Exception as e:
        logger.error(
            f"Error retrieving document statistics: {e}",
            extra={
                "correlation_id": correlation_id,
                "user_id": str(current_user.id)
            }
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve document statistics"
        )