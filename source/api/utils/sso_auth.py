"""
Path: infrastructure/source/api/utils/sso_auth.py
Version: 1
"""

import logging
from typing import Optional, Dict, Any, List
from datetime import datetime, timezone
from email_validator import validate_email, EmailNotValidError

from fastapi import Request, HTTPException, status
from ..models.auth import User
from ..models.base import UserRole
from ..database import get_users_collection, create_object_id, log_audit_event
from ..config import get_settings

logger = logging.getLogger(__name__)
settings = get_settings()


class SSOAuthenticator:
    """
    SSO authentication handler for reverse proxy integration
    
    Handles user authentication via headers set by reverse proxy/ingress
    when SSO is handled at the infrastructure level.
    """
    
    def __init__(self):
        self.user_header = settings.sso_header_user
        self.email_header = settings.sso_header_email
        self.roles_header = settings.sso_header_roles
        
        # Trusted header validation
        self.required_headers = [self.user_header, self.email_header]
        
        logger.info(f"SSO authenticator initialized with headers: {self.required_headers}")
    
    async def authenticate_from_headers(self, request: Request) -> Optional[User]:
        """
        Authenticate user from SSO headers set by reverse proxy
        
        Args:
            request: FastAPI request object with SSO headers
            
        Returns:
            Authenticated User object or None
        """
        if not settings.sso_enabled:
            return None
        
        try:
            # Extract headers
            headers = self._extract_sso_headers(request)
            if not headers:
                logger.debug("No valid SSO headers found")
                return None
            
            # Validate headers
            validation_result = self._validate_sso_headers(headers)
            if not validation_result['valid']:
                logger.warning(f"Invalid SSO headers: {validation_result['errors']}")
                return None
            
            # Get or create user
            user = await self._get_or_create_sso_user(headers)
            if user:
                # Update last activity
                await self._update_user_activity(user, request)
                logger.debug(f"SSO authentication successful for user: {user.email}")
            
            return user
            
        except Exception as e:
            logger.error(f"SSO authentication error: {e}")
            return None
    
    def _extract_sso_headers(self, request: Request) -> Optional[Dict[str, str]]:
        """Extract SSO headers from request"""
        headers = {}
        
        # Get required headers
        for header in self.required_headers:
            value = request.headers.get(header)
            if not value:
                logger.debug(f"Missing required SSO header: {header}")
                return None
            headers[header] = value.strip()
        
        # Get optional roles header
        roles_value = request.headers.get(self.roles_header)
        if roles_value:
            headers[self.roles_header] = roles_value.strip()
        
        return headers
    
    def _validate_sso_headers(self, headers: Dict[str, str]) -> Dict[str, Any]:
        """Validate SSO headers content"""
        result = {'valid': True, 'errors': []}
        
        # Validate user identifier
        user_id = headers.get(self.user_header)
        if not user_id or len(user_id.strip()) == 0:
            result['valid'] = False
            result['errors'].append("Empty user identifier")
        elif len(user_id) > 255:
            result['valid'] = False
            result['errors'].append("User identifier too long")
        
        # Validate email
        email = headers.get(self.email_header)
        if email:
            try:
                validate_email(email)
            except EmailNotValidError as e:
                result['valid'] = False
                result['errors'].append(f"Invalid email: {e}")
        else:
            result['valid'] = False
            result['errors'].append("Missing email")
        
        # Validate roles if present
        roles_str = headers.get(self.roles_header)
        if roles_str:
            roles = self._parse_roles(roles_str)
            if not roles:
                result['errors'].append("Invalid roles format")
        
        return result
    
    def _parse_roles(self, roles_str: str) -> List[UserRole]:
        """Parse roles string into UserRole enum values"""
        if not roles_str:
            return [UserRole.USER]  # Default role
        
        # Support common separators
        role_names = []
        for sep in [',', ';', '|', ' ']:
            if sep in roles_str:
                role_names = [r.strip() for r in roles_str.split(sep)]
                break
        
        if not role_names:
            role_names = [roles_str.strip()]
        
        roles = []
        for role_name in role_names:
            if not role_name:
                continue
                
            # Normalize role name
            role_name = role_name.upper().replace('-', '_')
            
            # Map common SSO role names to our UserRole enum
            role_mapping = {
                'ADMIN': UserRole.ADMIN,
                'ADMINISTRATOR': UserRole.ADMIN,
                'SUPER_ADMIN': UserRole.SUPER_ADMIN,
                'SUPERADMIN': UserRole.SUPER_ADMIN,
                'MANAGER': UserRole.MANAGER,
                'USER': UserRole.USER,
                'MEMBER': UserRole.USER,
                'EMPLOYEE': UserRole.USER,
                # Add more mappings as needed
            }
            
            role = role_mapping.get(role_name, UserRole.USER)
            if role not in roles:
                roles.append(role)
        
        return roles if roles else [UserRole.USER]
    
    async def _get_or_create_sso_user(self, headers: Dict[str, str]) -> Optional[User]:
        """Get existing user or create new one from SSO headers"""
        user_id = headers[self.user_header]
        email = headers[self.email_header].lower()
        roles_str = headers.get(self.roles_header, '')
        roles = self._parse_roles(roles_str)
        
        # Determine highest role
        primary_role = max(roles, key=lambda r: r.value) if roles else UserRole.USER
        
        collection = get_users_collection()
        
        try:
            # Try to find existing user by SSO ID first
            existing_user = await collection.find_one({
                "$or": [
                    {"sso_id": user_id},
                    {"email": email}
                ]
            })
            
            current_time = datetime.now(timezone.utc)
            
            if existing_user:
                # Update existing user
                update_data = {
                    "sso_id": user_id,
                    "email": email,
                    "role": primary_role,
                    "last_login": current_time,
                    "updated_at": current_time,
                    "is_active": True,
                    "email_verified": True  # SSO users are pre-verified
                }
                
                # Update name if we can derive it from email
                if not existing_user.get("name"):
                    name = self._derive_name_from_email(email)
                    if name:
                        update_data["name"] = name
                
                await collection.update_one(
                    {"_id": existing_user["_id"]},
                    {"$set": update_data}
                )
                
                logger.info(f"Updated SSO user: {email}")
                
                # Return updated user
                existing_user.update(update_data)
                return self._doc_to_user(existing_user)
            
            else:
                # Create new user
                name = self._derive_name_from_email(email)
                
                user_doc = {
                    "_id": create_object_id(),
                    "email": email,
                    "name": name or "SSO User",
                    "role": primary_role,
                    "sso_id": user_id,
                    "is_active": True,
                    "email_verified": True,
                    "password_hash": None,  # SSO users don't have passwords
                    "created_at": current_time,
                    "updated_at": current_time,
                    "last_login": current_time,
                    "failed_login_attempts": 0
                }
                
                await collection.insert_one(user_doc)
                
                logger.info(f"Created new SSO user: {email}")
                
                return self._doc_to_user(user_doc)
                
        except Exception as e:
            logger.error(f"Error managing SSO user {email}: {e}")
            return None
    
    def _derive_name_from_email(self, email: str) -> Optional[str]:
        """Derive display name from email address"""
        try:
            local_part = email.split('@')[0]
            
            # Replace common separators with spaces
            name = local_part.replace('.', ' ').replace('_', ' ').replace('-', ' ')
            
            # Capitalize words
            name = ' '.join(word.capitalize() for word in name.split())
            
            return name if name and len(name) <= 100 else None
            
        except Exception:
            return None
    
    async def _update_user_activity(self, user: User, request: Request):
        """Update user activity from SSO authentication"""
        try:
            collection = get_users_collection()
            
            await collection.update_one(
                {"_id": user.id},
                {
                    "$set": {
                        "last_login": datetime.now(timezone.utc),
                        "updated_at": datetime.now(timezone.utc)
                    }
                }
            )
            
            # Log audit event
            await log_audit_event(
                action="sso_authentication",
                user_id=str(user.id),
                details={
                    "email": user.email,
                    "sso_id": getattr(user, 'sso_id', None),
                    "client_ip": request.client.host if request.client else None,
                    "user_agent": request.headers.get("user-agent")
                },
                ip_address=request.client.host if request.client else None
            )
            
        except Exception as e:
            logger.error(f"Failed to update user activity: {e}")
    
    def _doc_to_user(self, user_doc: Dict[str, Any]) -> User:
        """Convert database document to User model"""
        return User(
            id=str(user_doc["_id"]),
            email=user_doc["email"],
            password_hash=user_doc.get("password_hash"),
            name=user_doc["name"],
            role=user_doc["role"],
            organization=user_doc.get("organization"),
            phone=user_doc.get("phone"),
            is_active=user_doc["is_active"],
            email_verified=user_doc.get("email_verified", False),
            sso_id=user_doc.get("sso_id"),
            last_login=user_doc.get("last_login"),
            failed_login_attempts=user_doc.get("failed_login_attempts", 0),
            locked_until=user_doc.get("locked_until"),
            created_at=user_doc["created_at"],
            updated_at=user_doc["updated_at"]
        )
    
    async def validate_sso_configuration(self) -> Dict[str, Any]:
        """Validate SSO configuration"""
        result = {
            'valid': True,
            'errors': [],
            'warnings': [],
            'config': {
                'enabled': settings.sso_enabled,
                'user_header': self.user_header,
                'email_header': self.email_header,
                'roles_header': self.roles_header,
                'required_headers': self.required_headers
            }
        }
        
        if settings.sso_enabled:
            if not self.user_header:
                result['valid'] = False
                result['errors'].append("Missing SSO user header configuration")
            
            if not self.email_header:
                result['valid'] = False
                result['errors'].append("Missing SSO email header configuration")
            
            if not settings.behind_reverse_proxy:
                result['warnings'].append("SSO enabled but not behind reverse proxy")
            
            if not settings.trust_proxy_headers:
                result['warnings'].append("SSO enabled but proxy headers not trusted")
        
        return result


# Global SSO authenticator instance
_sso_authenticator: Optional[SSOAuthenticator] = None


def get_sso_authenticator() -> SSOAuthenticator:
    """Get global SSO authenticator instance"""
    global _sso_authenticator
    
    if _sso_authenticator is None:
        _sso_authenticator = SSOAuthenticator()
    
    return _sso_authenticator


async def authenticate_sso_user(request: Request) -> Optional[User]:
    """
    Convenience function to authenticate user from SSO headers
    
    Args:
        request: FastAPI request object
        
    Returns:
        Authenticated user or None
    """
    if not settings.sso_enabled:
        return None
    
    authenticator = get_sso_authenticator()
    return await authenticator.authenticate_from_headers(request)