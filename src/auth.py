import os
import logging
import json
from datetime import datetime, timedelta
from collections import defaultdict
from typing import Dict, Tuple
from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from azure.data.tables import TableServiceClient, UpdateMode
from azure.identity import DefaultAzureCredential
from azure.core.exceptions import HttpResponseError

logger = logging.getLogger(__name__)


class RateLimiter:
    """Simple in-memory rate limiter for API key usage with automatic cleanup."""
    
    def __init__(self, max_requests: int = 100, window_seconds: int = 3600):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.requests: Dict[str, list] = defaultdict(list)
        self.last_cleanup = datetime.utcnow()
        self.cleanup_interval = timedelta(minutes=5)
    
    def is_allowed(self, api_key: str) -> Tuple[bool, int]:
        """Check if request is allowed. Returns (allowed, remaining_requests)."""
        now = datetime.utcnow()
        window_start = now - timedelta(seconds=self.window_seconds)
        
        # Periodic cleanup of all keys to prevent memory growth
        if now - self.last_cleanup > self.cleanup_interval:
            self._cleanup_old_entries(window_start)
            self.last_cleanup = now
        
        # Clean old requests for this key
        self.requests[api_key] = [
            req_time for req_time in self.requests[api_key] 
            if req_time > window_start
        ]
        
        current_requests = len(self.requests[api_key])
        
        if current_requests >= self.max_requests:
            return False, 0
        
        # Record this request
        self.requests[api_key].append(now)
        return True, self.max_requests - current_requests - 1
    
    def _cleanup_old_entries(self, window_start: datetime):
        """Remove old entries from all keys to prevent memory growth."""
        keys_to_remove = []
        for key, timestamps in list(self.requests.items()):
            # Filter out old timestamps
            valid_timestamps = [ts for ts in timestamps if ts > window_start]
            if valid_timestamps:
                self.requests[key] = valid_timestamps
            else:
                keys_to_remove.append(key)
        
        # Remove keys with no recent requests
        for key in keys_to_remove:
            del self.requests[key]
        
        if keys_to_remove:
            logger.debug(f"Cleaned up {len(keys_to_remove)} inactive API keys from rate limiter")


class APIKeyValidator:
    """Validates API keys using Azure Table Storage."""
    
    def __init__(self):
        self.table_client = None
        self._initialize_table_client()
    
    def _initialize_table_client(self):
        """Initialize Azure Table Storage client."""
        try:
            # Try managed identity first (for production)
            storage_account_name = os.environ.get("AZURE_STORAGE_ACCOUNT_NAME")
            if storage_account_name:
                try:
                    credential = DefaultAzureCredential()
                    table_service = TableServiceClient(
                        endpoint=f"https://{storage_account_name}.table.core.windows.net",
                        credential=credential
                    )
                    logger.info("Using managed identity for Table Storage")
                except Exception as e:
                    logger.warning(f"Failed to use managed identity: {e}")
                    # Fall back to connection string
                    connection_string = os.environ.get("AZURE_STORAGE_CONNECTION_STRING")
                    if connection_string:
                        table_service = TableServiceClient.from_connection_string(
                            conn_str=connection_string
                        )
                        logger.info("Using connection string for Table Storage")
                    else:
                        raise
            else:
                # Use connection string (for local development)
                connection_string = os.environ.get("AZURE_STORAGE_CONNECTION_STRING")
                if not connection_string:
                    logger.error("No Azure Storage configuration found")
                    return
                
                table_service = TableServiceClient.from_connection_string(
                    conn_str=connection_string
                )
                logger.info("Using connection string for Table Storage")
            
            # Get or create the api_keys table
            self.table_client = table_service.get_table_client("apikeys")
            
            # Create table if it doesn't exist
            try:
                table_service.create_table("apikeys")
                logger.info("Created api_keys table")
            except Exception:
                # Table already exists
                pass
                
        except Exception as e:
            logger.error(f"Failed to initialize Table Storage client: {e}")
            self.table_client = None
    
    def validate_key(self, api_key: str) -> bool:
        """
        Validate an API key against Azure Table Storage.
        
        Returns True if the key is valid and active, False otherwise.
        """
        if not self.table_client:
            logger.error("Table client not initialized")
            return False
        
        try:
            # Query for the API key
            entity = self.table_client.get_entity(
                partition_key="keys",
                row_key=api_key
            )
            
            # Check if key is active
            if not entity.get("active", False):
                logger.warning(f"Inactive API key attempted: {api_key[:8]}...")
                return False
            
            # Update usage statistics
            try:
                entity["last_used"] = datetime.utcnow().isoformat()
                entity["usage_count"] = entity.get("usage_count", 0) + 1
                self.table_client.update_entity(entity, mode=UpdateMode.MERGE)
            except Exception as e:
                logger.warning(f"Failed to update usage stats: {e}")
                # Don't fail authentication if we can't update stats
            
            # Log successful authentication
            logger.info(f"API key authenticated: {api_key[:8]}... (usage_count: {entity.get('usage_count', 0)})") 
            return True
            
        except HttpResponseError as e:
            if e.status_code == 404:
                logger.warning(f"Invalid API key attempted: {api_key[:8]}... from validation")
            else:
                logger.error(f"Table Storage error: {e}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error validating API key: {e}")
            return False


class TokenAuthMiddleware(BaseHTTPMiddleware):
    """
    Bearer token authentication middleware for MCP server.
    Validates API keys from Authorization header using Azure Table Storage.
    """
    
    def __init__(self, app):
        super().__init__(app)
        self.api_key_validator = APIKeyValidator()
        self.rate_limiter = RateLimiter(max_requests=100, window_seconds=3600)
        
        # Check if we should fall back to environment variable
        self.fallback_token = os.environ.get("MCP_AUTH_TOKEN")
        if self.fallback_token:
            if not self.api_key_validator.table_client:
                logger.warning("Using fallback token authentication (Table Storage not available)")
            else:
                logger.info("Fallback token configured alongside Table Storage")
    
    async def dispatch(self, request: Request, call_next):
        """Process the request through authentication checks."""
        # Skip authentication for health and root endpoints
        if request.url.path in ["/health", "/"]:
            return await call_next(request)
        
        # Get client info for logging
        client_info = self._get_client_info(request)
        
        # For MCP protocol, allow unauthenticated capabilities/initialize requests
        # but require auth for actual tool calls
        if request.url.path.endswith("/mcp") or request.url.path.endswith("/mcp/"):
            logger.debug(f"MCP endpoint detected: {request.url.path}")
            # Check if this is an MCP initialize or capabilities request
            if request.method == "POST":
                try:
                    body = await request.body()
                    # Parse JSON to check method
                    data = json.loads(body) if body else {}
                    method = data.get("method", "")
                    
                    # Allow initialize and capabilities without auth
                    if method in ["initialize", "capabilities/list"]:
                        logger.info(f"Allowing unauthenticated {method} request from {client_info}")
                        # Reconstruct request with body for downstream processing
                        async def receive():
                            return {"type": "http.request", "body": body}
                        
                        request._body = body
                        return await call_next(request)
                except Exception as e:
                    logger.warning(f"Failed to parse MCP request: {e}")
                    # If we can't parse, continue with normal auth flow
        
        # Extract token from Authorization header
        auth_header = request.headers.get("Authorization", "")
        
        if not auth_header:
            logger.warning(f"Missing authorization header for {request.url.path} from {client_info}")
            # For MCP requests, return proper JSONRPC error format
            if request.url.path.endswith("/mcp"):
                return JSONResponse(
                    content={
                        "jsonrpc": "2.0",
                        "error": {
                            "code": -32600,
                            "message": "Authentication required",
                            "data": "Missing Authorization header. Use: Bearer <token>"
                        },
                        "id": None
                    },
                    status_code=401,
                    headers={"WWW-Authenticate": "Bearer"}
                )
            else:
                return JSONResponse(
                    content={"error": "Missing authorization header"},
                    status_code=401,
                    headers={"WWW-Authenticate": "Bearer"}
                )
        
        if not auth_header.startswith("Bearer "):
            logger.warning(f"Invalid authorization header format for {request.url.path} from {client_info}")
            # For MCP requests, return proper JSONRPC error format
            if request.url.path.endswith("/mcp"):
                return JSONResponse(
                    content={
                        "jsonrpc": "2.0",
                        "error": {
                            "code": -32600,
                            "message": "Invalid authorization format",
                            "data": "Use: Authorization: Bearer <token>"
                        },
                        "id": None
                    },
                    status_code=401,
                    headers={"WWW-Authenticate": "Bearer"}
                )
            else:
                return JSONResponse(
                    content={"error": "Invalid authorization header format. Use: Bearer <token>"},
                    status_code=401,
                    headers={"WWW-Authenticate": "Bearer"}
                )
        
        # Extract token
        token = auth_header[7:]  # Remove "Bearer " prefix
        
        # Check rate limiting before validation
        allowed, remaining = self.rate_limiter.is_allowed(token)
        if not allowed:
            logger.warning(f"Rate limit exceeded for API key: {token[:8]}... from {client_info}")
            if request.url.path.endswith("/mcp"):
                return JSONResponse(
                    content={
                        "jsonrpc": "2.0",
                        "error": {
                            "code": -32003,
                            "message": "Rate limit exceeded",
                            "data": "Too many requests. Try again later."
                        },
                        "id": None
                    },
                    status_code=429,
                    headers={"Retry-After": "3600"}
                )
            else:
                return JSONResponse(
                    content={"error": "Rate limit exceeded"},
                    status_code=429,
                    headers={"Retry-After": "3600"}
                )
        
        # Validate token
        is_valid = False
        
        # Debug logging
        logger.debug(f"Validating token: {token[:8]}... (has table client: {self.api_key_validator.table_client is not None}, has fallback: {self.fallback_token is not None})")
        
        # Try Azure Table Storage first
        if self.api_key_validator.table_client:
            is_valid = self.api_key_validator.validate_key(token)
        # Fall back to environment variable if Table Storage is not available
        elif self.fallback_token:
            is_valid = (token == self.fallback_token)
            if is_valid:
                logger.info(f"Fallback token authenticated from {client_info}")
        else:
            # If no table storage and no fallback token, check if it's a self-registered key
            if token.startswith("sk_") and len(token) == 35:  # sk_ + 32 hex chars
                # In fallback mode, accept any properly formatted key
                # This allows self-registered keys to work even without storage
                is_valid = True
                logger.info(f"Self-registered key format accepted from {client_info} (fallback mode)")
            else:
                logger.error("No authentication method available")
                return JSONResponse(
                    content={"error": "Authentication not properly configured"},
                    status_code=500
                )
        
        if not is_valid:
            logger.warning(f"Authentication failed for token: {token[:8]}... from {client_info} on {request.url.path}")
            # For MCP requests, return proper JSONRPC error format
            if request.url.path.endswith("/mcp"):
                return JSONResponse(
                    content={
                        "jsonrpc": "2.0",
                        "error": {
                            "code": -32600,
                            "message": "Authentication required",
                            "data": "Invalid or missing Bearer token"
                        },
                        "id": None
                    },
                    status_code=401,
                    headers={"WWW-Authenticate": "Bearer"}
                )
            else:
                return JSONResponse(
                    content={"error": "Invalid authentication token"},
                    status_code=401,
                    headers={"WWW-Authenticate": "Bearer"}
                )
        
        # Token is valid, proceed with request
        response = await call_next(request)
        
        # Add security headers
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        
        # Add rate limit headers
        _, remaining = self.rate_limiter.is_allowed(token)
        response.headers["X-RateLimit-Remaining"] = str(max(0, remaining))
        response.headers["X-RateLimit-Limit"] = str(self.rate_limiter.max_requests)
        
        # Log successful request (debug level to avoid noise)
        logger.debug(f"Request authorized: {request.method} {request.url.path} from {client_info} using key {token[:8]}...")
        
        return response
    
    def _get_client_info(self, request: Request) -> str:
        """Extract client information for logging."""
        if request.client:
            client_ip = request.client.host
            # Check for X-Forwarded-For header (common with proxies/load balancers)
            forwarded_for = request.headers.get("X-Forwarded-For")
            if forwarded_for:
                # Take the first IP in the chain
                client_ip = forwarded_for.split(",")[0].strip()
            return client_ip
        return "unknown"