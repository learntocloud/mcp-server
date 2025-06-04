"""
API Key Registration System for CTF Users
Allows public registration for API keys with rate limiting and abuse prevention.
"""

import os
import uuid
import hashlib
import logging
import re
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
from collections import defaultdict
from pydantic import BaseModel, validator
from fastapi import HTTPException
from azure.data.tables import TableServiceClient, UpdateMode
from azure.identity import DefaultAzureCredential
from azure.core.exceptions import ResourceExistsError, HttpResponseError

logger = logging.getLogger(__name__)


class RegistrationRequest(BaseModel):
    email: str
    project_name: str
    github_repo: Optional[str] = None
    organization: Optional[str] = None
    
    @validator('email')
    def validate_email(cls, v):
        # Simple email validation regex
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if not re.match(email_pattern, v):
            raise ValueError('Invalid email format')
        return v.lower().strip()
    
    @validator('project_name')
    def validate_project_name(cls, v):
        if len(v.strip()) < 3:
            raise ValueError('Project name must be at least 3 characters')
        if len(v) > 100:
            raise ValueError('Project name must be less than 100 characters')
        return v.strip()
    
    @validator('github_repo')
    def validate_github_repo(cls, v):
        if v and not v.startswith(('http://github.com/', 'https://github.com/', 'github.com/')):
            if '/' not in v:
                raise ValueError('GitHub repo should be in format: username/repo')
        return v


class RegistrationResponse(BaseModel):
    api_key: str
    message: str
    rate_limit: str
    created: str
    docs_url: str = "https://github.com/your-username/mcp-server#usage"
    expires: Optional[str] = None


class RegistrationRateLimiter:
    """Rate limiter for registration requests."""
    
    def __init__(self, max_registrations: int = 5, window_hours: int = 24):
        self.max_registrations = max_registrations
        self.window_hours = window_hours
        self.registrations: Dict[str, list] = defaultdict(list)
        self.last_cleanup = datetime.utcnow()
        self.cleanup_interval = timedelta(hours=1)
    
    def is_allowed(self, email_hash: str) -> tuple[bool, int]:
        """Check if registration is allowed for this email hash."""
        now = datetime.utcnow()
        window_start = now - timedelta(hours=self.window_hours)
        
        # Periodic cleanup
        if now - self.last_cleanup > self.cleanup_interval:
            self._cleanup_old_entries(window_start)
            self.last_cleanup = now
        
        # Clean old registrations for this email
        self.registrations[email_hash] = [
            reg_time for reg_time in self.registrations[email_hash]
            if reg_time > window_start
        ]
        
        current_count = len(self.registrations[email_hash])
        
        if current_count >= self.max_registrations:
            return False, 0
        
        # Record this registration attempt
        self.registrations[email_hash].append(now)
        return True, self.max_registrations - current_count - 1
    
    def _cleanup_old_entries(self, window_start: datetime):
        """Clean up old entries to prevent memory growth."""
        emails_to_remove = []
        for email_hash, timestamps in list(self.registrations.items()):
            valid_timestamps = [ts for ts in timestamps if ts > window_start]
            if valid_timestamps:
                self.registrations[email_hash] = valid_timestamps
            else:
                emails_to_remove.append(email_hash)
        
        for email_hash in emails_to_remove:
            del self.registrations[email_hash]
        
        if emails_to_remove:
            logger.debug(f"Cleaned up {len(emails_to_remove)} inactive email hashes from registration rate limiter")


class APIKeyRegistrationManager:
    """Manages API key registration and storage."""
    
    def __init__(self):
        self.table_client = None
        self.fallback_mode = False
        self.rate_limiter = RegistrationRateLimiter(
            max_registrations=int(os.environ.get("REGISTRATION_RATE_LIMIT", "5")),
            window_hours=int(os.environ.get("REGISTRATION_WINDOW_HOURS", "24"))
        )
        self._initialize_storage()
    
    def _initialize_storage(self):
        """Initialize storage backend (Azure Table Storage or fallback)."""
        try:
            # Try Azure Table Storage first
            storage_account_name = os.environ.get("AZURE_STORAGE_ACCOUNT_NAME")
            if storage_account_name:
                try:
                    credential = DefaultAzureCredential()
                    table_service = TableServiceClient(
                        endpoint=f"https://{storage_account_name}.table.core.windows.net",
                        credential=credential
                    )
                    self.table_client = table_service.get_table_client("registrations")
                    
                    # Create table if it doesn't exist
                    try:
                        table_service.create_table("registrations")
                        logger.info("Created registrations table")
                    except ResourceExistsError:
                        logger.info("Using existing registrations table")
                    
                    logger.info("Registration system using Azure Table Storage")
                    return
                    
                except Exception as e:
                    logger.warning(f"Failed to initialize Azure Table Storage for registrations: {e}")
            
            # Fall back to connection string
            connection_string = os.environ.get("AZURE_STORAGE_CONNECTION_STRING")
            if connection_string:
                table_service = TableServiceClient.from_connection_string(conn_str=connection_string)
                self.table_client = table_service.get_table_client("registrations")
                
                try:
                    table_service.create_table("registrations")
                    logger.info("Created registrations table")
                except ResourceExistsError:
                    logger.info("Using existing registrations table")
                
                logger.info("Registration system using Azure Table Storage (connection string)")
                return
            
            # No storage available - use fallback mode
            logger.warning("No Azure Storage available for registrations - using fallback mode")
            self.fallback_mode = True
            
        except Exception as e:
            logger.error(f"Failed to initialize registration storage: {e}")
            self.fallback_mode = True
    
    def _hash_email(self, email: str) -> str:
        """Create a hash of the email for privacy."""
        return hashlib.sha256(email.lower().encode()).hexdigest()
    
    async def check_existing_registration(self, email_hash: str) -> Optional[str]:
        """Check if email is already registered."""
        if self.fallback_mode:
            # In fallback mode, allow multiple registrations
            return None
        
        try:
            entity = self.table_client.get_entity(
                partition_key="registrations",
                row_key=email_hash
            )
            if entity.get("active", False):
                return entity.get("api_key_preview", "sk_***")
            return None
        except HttpResponseError as e:
            if e.status_code == 404:
                return None  # Not found, can register
            raise
    
    async def create_registration(self, request: RegistrationRequest) -> RegistrationResponse:
        """Create a new API key registration."""
        email_hash = self._hash_email(request.email)
        
        # Check rate limiting
        allowed, remaining = self.rate_limiter.is_allowed(email_hash)
        if not allowed:
            raise HTTPException(
                status_code=429,
                detail={
                    "error": "Rate limit exceeded",
                    "message": f"Too many registrations from this email. Try again in {self.rate_limiter.window_hours} hours.",
                    "retry_after": f"{self.rate_limiter.window_hours}h"
                }
            )
        
        # Check for existing registration
        existing_key = await self.check_existing_registration(email_hash)
        if existing_key:
            raise HTTPException(
                status_code=409,
                detail={
                    "error": "Already registered",
                    "message": "This email is already registered. Check your email for the existing API key.",
                    "api_key_preview": existing_key
                }
            )
        
        # Generate new API key
        key_id = uuid.uuid4().hex
        api_key = f"sk_{key_id}"
        created_time = datetime.utcnow()
        
        # Calculate expiration (optional - for CTF events)
        expires = None
        ctf_duration_days = os.environ.get("CTF_KEY_EXPIRY_DAYS")
        if ctf_duration_days:
            expires = created_time + timedelta(days=int(ctf_duration_days))
        
        # Store registration
        if not self.fallback_mode:
            registration_entity = {
                "PartitionKey": "registrations",
                "RowKey": email_hash,
                "api_key": api_key,
                "api_key_preview": f"{api_key[:8]}...",
                "project_name": request.project_name,
                "github_repo": request.github_repo or "",
                "organization": request.organization or "",
                "created": created_time.isoformat(),
                "expires": expires.isoformat() if expires else "",
                "active": True,
                "usage_count": 0,
                "last_used": "",
                "rate_limit": "1000/hour"
            }
            
            try:
                self.table_client.create_entity(registration_entity)
            except Exception as e:
                logger.error(f"Failed to store registration: {e}")
                # Continue anyway - user gets the key
        
        # Also store in API keys table for authentication
        await self._store_api_key(api_key, request, created_time, expires)
        
        # Log registration (without sensitive data)
        logger.info(f"New registration: project='{request.project_name}', repo='{request.github_repo}', key={api_key[:8]}...")
        
        return RegistrationResponse(
            api_key=api_key,
            message="API key created successfully! Save this key securely - it won't be shown again.",
            rate_limit="1000 requests/hour",
            created=created_time.isoformat(),
            expires=expires.isoformat() if expires else None
        )
    
    async def _store_api_key(self, api_key: str, request: RegistrationRequest, created_time: datetime, expires: Optional[datetime]):
        """Store the API key in the main apikeys table for authentication."""
        try:
            if self.table_client and not self.fallback_mode:
                # Get the storage account name and create a new table service client
                storage_account_name = os.environ.get("AZURE_STORAGE_ACCOUNT_NAME")
                if storage_account_name:
                    # Use the same credential method as the registration table
                    try:
                        credential = DefaultAzureCredential()
                        table_service = TableServiceClient(
                            endpoint=f"https://{storage_account_name}.table.core.windows.net",
                            credential=credential
                        )
                    except Exception:
                        # Fall back to connection string
                        connection_string = os.environ.get("AZURE_STORAGE_CONNECTION_STRING")
                        if connection_string:
                            table_service = TableServiceClient.from_connection_string(conn_str=connection_string)
                        else:
                            raise
                    
                    # Get the apikeys table client
                    apikeys_table = table_service.get_table_client("apikeys")
                    
                    # Create API key entity
                    api_key_entity = {
                        "PartitionKey": "keys",
                        "RowKey": api_key,
                        "active": True,
                        "created": created_time.isoformat(),
                        "expires": expires.isoformat() if expires else "",
                        "description": f"Self-registered: {request.project_name}",
                        "usage_count": 0,
                        "last_used": "",
                        "source": "self_registration",
                        "project_name": request.project_name,
                        "github_repo": request.github_repo or ""
                    }
                    
                    apikeys_table.create_entity(api_key_entity)
                    logger.info(f"Successfully stored API key {api_key[:8]}... in apikeys table")
                    
        except Exception as e:
            logger.warning(f"Failed to store API key in apikeys table: {e}")
            # This is not critical - the key can still work with fallback auth


# Global instance
registration_manager = APIKeyRegistrationManager()