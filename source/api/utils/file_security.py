"""
Path: infrastructure/source/api/utils/file_security.py
Version: 1
"""

import os
import magic
import hashlib
import tempfile
import logging
from typing import Dict, List, Optional, Tuple, BinaryIO, Any
from pathlib import Path
import re

from fastapi import HTTPException, status, UploadFile

logger = logging.getLogger(__name__)

# File type security configuration
DANGEROUS_EXTENSIONS = {
    '.exe', '.bat', '.cmd', '.com', '.pif', '.scr', '.vbs', '.js', '.jar',
    '.msi', '.dll', '.scf', '.lnk', '.inf', '.reg', '.sh', '.bash', '.ps1',
    '.php', '.asp', '.jsp', '.py', '.rb', '.pl', '.go', '.class'
}

# Magic number signatures for common file types
MAGIC_SIGNATURES = {
    'application/pdf': [b'%PDF'],
    'image/jpeg': [b'\xff\xd8\xff'],
    'image/png': [b'\x89PNG\r\n\x1a\n'],
    'image/gif': [b'GIF87a', b'GIF89a'],
    'image/webp': [b'RIFF', b'WEBP'],
    'application/zip': [b'PK\x03\x04', b'PK\x05\x06', b'PK\x07\x08'],
    'application/msword': [b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1'],
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document': [
        b'PK\x03\x04'  # DOCX is a ZIP file
    ],
    'text/plain': []  # Text files have no magic signature
}

# Suspicious patterns in file names
SUSPICIOUS_NAME_PATTERNS = [
    r'\.\.', r'[<>:"|?*]', r'^(con|prn|aux|nul|com[1-9]|lpt[1-9])(\.|$)',
    r'[\x00-\x1f\x7f-\x9f]', r'\.(exe|bat|cmd|com|pif|scr)(\.|$)',
    r'%[0-9a-fA-F]{2}', r'javascript:', r'data:', r'vbscript:'
]

# Known malicious file patterns
MALWARE_PATTERNS = [
    # Script injection patterns
    b'<script', b'javascript:', b'vbscript:', b'onload=', b'onerror=',
    # Executable patterns
    b'MZ\x90\x00', b'\x7fELF', b'\xca\xfe\xba\xbe',  # PE, ELF, Mach-O
    # Archive bombs patterns
    b'PK\x03\x04' + b'\x00' * 26 + b'\xff' * 4,  # Potential zip bomb signature
    # PHP/ASP injection
    b'<?php', b'<% ', b'<%@'
]


class FileSecurityValidator:
    """
    Comprehensive file upload security validator
    
    Validates file types, sizes, names, and content for security threats.
    """
    
    def __init__(
        self,
        max_file_size: int = 100 * 1024 * 1024,  # 100MB
        allowed_mime_types: Optional[List[str]] = None,
        scan_content: bool = True,
        quarantine_path: Optional[str] = None
    ):
        self.max_file_size = max_file_size
        self.allowed_mime_types = allowed_mime_types or [
            'application/pdf',
            'application/msword',
            'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
            'text/plain',
            'image/jpeg',
            'image/png',
            'image/webp'
        ]
        self.scan_content = scan_content
        self.quarantine_path = quarantine_path
        
        # Initialize libmagic if available
        self.magic_mime = None
        try:
            self.magic_mime = magic.Magic(mime=True)
        except Exception as e:
            logger.warning(f"libmagic not available, using basic MIME detection: {e}")
    
    async def validate_upload(self, file: UploadFile) -> Dict[str, Any]:
        """
        Comprehensive validation of uploaded file
        
        Args:
            file: FastAPI UploadFile object
            
        Returns:
            Validation result dictionary
            
        Raises:
            HTTPException: If file fails security validation
        """
        result = {
            'valid': False,
            'filename': file.filename,
            'original_mime': file.content_type,
            'detected_mime': None,
            'size': 0,
            'hash': None,
            'threats': [],
            'warnings': []
        }
        
        try:
            # 1. Validate filename
            filename_result = self._validate_filename(file.filename)
            if not filename_result['valid']:
                result['threats'].extend(filename_result['threats'])
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Invalid filename: {'; '.join(filename_result['threats'])}"
                )
            
            # 2. Read file content for validation
            content = await file.read()
            result['size'] = len(content)
            
            # Reset file position for later use
            await file.seek(0)
            
            # 3. Validate file size
            if result['size'] > self.max_file_size:
                raise HTTPException(
                    status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                    detail=f"File too large: {result['size']} bytes (max: {self.max_file_size})"
                )
            
            if result['size'] == 0:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Empty file not allowed"
                )
            
            # 4. Calculate file hash
            result['hash'] = hashlib.sha256(content).hexdigest()
            
            # 5. Detect actual MIME type
            mime_result = self._detect_mime_type(content, file.filename)
            result['detected_mime'] = mime_result['mime_type']
            result['warnings'].extend(mime_result['warnings'])
            
            # 6. Validate MIME type
            if result['detected_mime'] not in self.allowed_mime_types:
                result['threats'].append(f"File type not allowed: {result['detected_mime']}")
                raise HTTPException(
                    status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
                    detail=f"File type not allowed: {result['detected_mime']}"
                )
            
            # 7. Check MIME type spoofing
            if file.content_type and file.content_type != result['detected_mime']:
                result['warnings'].append(
                    f"MIME type mismatch: claimed {file.content_type}, detected {result['detected_mime']}"
                )
            
            # 8. Scan content for malicious patterns
            if self.scan_content:
                content_result = self._scan_content(content)
                if content_result['threats']:
                    result['threats'].extend(content_result['threats'])
                    
                    # Quarantine if configured
                    if self.quarantine_path:
                        await self._quarantine_file(content, result['hash'])
                    
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail=f"Malicious content detected: {'; '.join(content_result['threats'])}"
                    )
            
            result['valid'] = True
            logger.info(f"File validation successful: {file.filename} ({result['detected_mime']}, {result['size']} bytes)")
            
            return result
            
        except HTTPException:
            # Re-raise HTTP exceptions
            raise
        except Exception as e:
            logger.error(f"File validation error: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="File validation failed"
            )
    
    def _validate_filename(self, filename: Optional[str]) -> Dict[str, Any]:
        """Validate filename for security issues"""
        result = {'valid': True, 'threats': []}
        
        if not filename:
            result['valid'] = False
            result['threats'].append("Missing filename")
            return result
        
        # Check length
        if len(filename) > 255:
            result['valid'] = False
            result['threats'].append("Filename too long")
        
        # Check for suspicious patterns
        for pattern in SUSPICIOUS_NAME_PATTERNS:
            if re.search(pattern, filename, re.IGNORECASE):
                result['valid'] = False
                result['threats'].append(f"Suspicious filename pattern: {pattern}")
        
        # Check dangerous extensions
        file_path = Path(filename)
        if file_path.suffix.lower() in DANGEROUS_EXTENSIONS:
            result['valid'] = False
            result['threats'].append(f"Dangerous file extension: {file_path.suffix}")
        
        # Check for multiple extensions (potential evasion)
        parts = filename.split('.')
        if len(parts) > 3:  # filename.ext1.ext2.ext3
            result['threats'].append("Multiple file extensions detected")
        
        return result
    
    def _detect_mime_type(self, content: bytes, filename: Optional[str]) -> Dict[str, Any]:
        """Detect actual MIME type from content"""
        result = {'mime_type': 'application/octet-stream', 'warnings': []}
        
        # Try libmagic first
        if self.magic_mime:
            try:
                mime_type = self.magic_mime.from_buffer(content)
                if mime_type:
                    result['mime_type'] = mime_type
                    return result
            except Exception as e:
                result['warnings'].append(f"libmagic detection failed: {e}")
        
        # Fallback to magic signatures
        for mime_type, signatures in MAGIC_SIGNATURES.items():
            if not signatures:  # Text files
                if self._is_text_content(content):
                    result['mime_type'] = mime_type
                    break
                continue
                
            for signature in signatures:
                if content.startswith(signature):
                    result['mime_type'] = mime_type
                    return result
        
        # Fallback to extension-based detection
        if filename:
            ext = Path(filename).suffix.lower()
            if ext == '.pdf':
                result['mime_type'] = 'application/pdf'
            elif ext in ['.jpg', '.jpeg']:
                result['mime_type'] = 'image/jpeg'
            elif ext == '.png':
                result['mime_type'] = 'image/png'
            elif ext == '.txt':
                result['mime_type'] = 'text/plain'
            elif ext == '.doc':
                result['mime_type'] = 'application/msword'
            elif ext == '.docx':
                result['mime_type'] = 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
        
        return result
    
    def _is_text_content(self, content: bytes) -> bool:
        """Check if content appears to be text"""
        try:
            # Try to decode as UTF-8
            content.decode('utf-8')
            
            # Check for high ratio of printable characters
            printable_chars = sum(1 for b in content if 32 <= b <= 126 or b in [9, 10, 13])
            if len(content) == 0:
                return False
            
            printable_ratio = printable_chars / len(content)
            return printable_ratio > 0.95
            
        except UnicodeDecodeError:
            return False
    
    def _scan_content(self, content: bytes) -> Dict[str, Any]:
        """Scan file content for malicious patterns"""
        result = {'threats': []}
        
        # Check for known malware patterns
        for pattern in MALWARE_PATTERNS:
            if pattern in content:
                result['threats'].append(f"Malicious pattern detected: {pattern[:10].hex()}")
        
        # Check for potential zip bombs (basic detection)
        if content.startswith(b'PK'):  # ZIP file
            if self._detect_zip_bomb(content):
                result['threats'].append("Potential zip bomb detected")
        
        # Check for embedded executables
        if b'MZ\x90\x00' in content and not content.startswith(b'PK'):
            result['threats'].append("Embedded executable detected")
        
        # Check for excessive null bytes (potential binary padding)
        null_count = content.count(b'\x00')
        if len(content) > 1000 and null_count / len(content) > 0.9:
            result['threats'].append("Excessive null bytes (potential binary padding)")
        
        return result
    
    def _detect_zip_bomb(self, content: bytes) -> bool:
        """Basic zip bomb detection"""
        try:
            import zipfile
            import io
            
            with zipfile.ZipFile(io.BytesIO(content)) as zf:
                total_uncompressed = 0
                total_compressed = len(content)
                
                for info in zf.infolist():
                    total_uncompressed += info.file_size
                    
                    # Check compression ratio
                    if info.compress_size > 0:
                        ratio = info.file_size / info.compress_size
                        if ratio > 1000:  # Suspicious compression ratio
                            return True
                
                # Check total compression ratio
                if total_compressed > 0 and total_uncompressed / total_compressed > 1000:
                    return True
                
        except Exception:
            # If we can't parse the zip, it might be malformed
            pass
        
        return False
    
    async def _quarantine_file(self, content: bytes, file_hash: str):
        """Quarantine suspicious file"""
        if not self.quarantine_path:
            return
        
        try:
            quarantine_dir = Path(self.quarantine_path)
            quarantine_dir.mkdir(parents=True, exist_ok=True)
            
            quarantine_file = quarantine_dir / f"quarantine_{file_hash}.bin"
            
            with open(quarantine_file, 'wb') as f:
                f.write(content)
            
            logger.warning(f"File quarantined: {quarantine_file}")
            
        except Exception as e:
            logger.error(f"Failed to quarantine file: {e}")


# Global validator instance
_file_validator: Optional[FileSecurityValidator] = None


def get_file_validator(
    max_file_size: int = 100 * 1024 * 1024,
    allowed_mime_types: Optional[List[str]] = None,
    scan_content: bool = True,
    quarantine_path: Optional[str] = None
) -> FileSecurityValidator:
    """
    Get global file security validator instance
    
    Returns:
        FileSecurityValidator instance
    """
    global _file_validator
    
    if _file_validator is None:
        _file_validator = FileSecurityValidator(
            max_file_size=max_file_size,
            allowed_mime_types=allowed_mime_types,
            scan_content=scan_content,
            quarantine_path=quarantine_path
        )
    
    return _file_validator


async def validate_file_upload(file: UploadFile) -> Dict[str, Any]:
    """
    Convenience function to validate file upload
    
    Args:
        file: UploadFile to validate
        
    Returns:
        Validation result
    """
    validator = get_file_validator()
    return await validator.validate_upload(file)