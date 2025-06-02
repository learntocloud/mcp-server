import os
import secrets
import pandas as pd
import json
from fastapi import FastAPI, HTTPException, status, Header
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware import Middleware
from typing import Optional, Dict
from fastmcp import FastMCP

# Global DataFrame for API keys
API_KEYS = pd.DataFrame()

def load_api_keys_from_json_env():
    """Load API keys from JSON environment variable"""
    global API_KEYS
    
    env_keys = os.environ.get('API_KEYS_JSON')
    if not env_keys:
        print("No API_KEYS_JSON environment variable found")
        return False
    
    try:
        keys_data = json.loads(env_keys)
        API_KEYS = pd.DataFrame(keys_data)
        print(f"Loaded {len(API_KEYS)} API keys from API_KEYS_JSON environment variable")
        
        # Validate required columns
        required_columns = ['CTF_Name', 'API_KEY', 'READ', 'WRITE', 'ACTIVE']
        if not all(col in API_KEYS.columns for col in required_columns):
            print(f"Missing required columns. Expected: {required_columns}")
            print(f"Found: {list(API_KEYS.columns)}")
            return False
        
        # Convert boolean columns to proper boolean type
        for col in ['READ', 'WRITE', 'ACTIVE']:
            API_KEYS[col] = API_KEYS[col].astype(bool)
        
        return True
        
    except json.JSONDecodeError as e:
        print(f"Error parsing API_KEYS_JSON: {e}")
        return False
    except Exception as e:
        print(f"Error loading API keys: {e}")
        return False

def initialize_api_keys():
    """Initialize API keys from JSON environment variable"""
    print("Initializing API keys from environment...")
    
    if not load_api_keys_from_json_env():
        create_default_api_keys()
    
    if not API_KEYS.empty:
        print(f"API Keys loaded:")
        for _, row in API_KEYS.iterrows():
            status = "ACTIVE" if row['ACTIVE'] else "INACTIVE"
            perms = []
            if row['READ']: perms.append("READ")
            if row['WRITE']: perms.append("WRITE")
            print(f"  - {row['CTF_Name']}: {status} ({', '.join(perms)})")

def verify_api_key(x_api_key: Optional[str] = Header(None)) -> Dict:
    """Verify API key from X-API-Key header"""
    if not x_api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="X-API-Key header required"
        )
    
    if API_KEYS.empty:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="No API keys configured"
        )
    
    # Query DataFrame for the API key
    key_match = API_KEYS[API_KEYS['API_KEY'] == x_api_key]
    
    if key_match.empty:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key"
        )
    
    # Get the first (and should be only) matching row
    key_info = key_match.iloc[0]
    
    if not key_info['ACTIVE']:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="API key is inactive"
        )
    
    return {
        'ctf_name': key_info['CTF_Name'],
        'read': 'Read access is: f'{key_info['READ']}',
        'write': 'Write access is: f'{key_info['WRITE']}',
        'active': 'API_KEY is f'{key_info['ACTIVE']}'
    }

def get_active_keys() -> pd.DataFrame:
    """Get all active API keys"""
    if API_KEYS.empty:
        return pd.DataFrame()
    return API_KEYS[API_KEYS['ACTIVE'] == True]

def add_api_key(ctf_name: str, read: bool = True, write: bool = True) -> str:
    """Add new API key to DataFrame"""
    global API_KEYS
    
    # Generate new API key
    new_key = f"ctf-{ctf_name.lower().replace(' ', '-')}-key-{secrets.token_urlsafe(16)}"
    
    # Create new row as DataFrame
    new_row = pd.DataFrame({
        'CTF_Name': [ctf_name],
        'API_KEY': [new_key],
        'READ': [read],
        'WRITE': [write],
        'ACTIVE': [True]
    })
    
    # If API_KEYS is empty, initialize with proper schema
    if API_KEYS.empty:
        API_KEYS = new_row
    else:
        API_KEYS = pd.concat([API_KEYS, new_row], ignore_index=True)
    
    return new_key

# Create MCP server instance  
mcp = FastMCP(
    name="MCP Server",
    dependencies=["httpx", "fastapi", "uvicorn[standard]", "pandas"]
)

# Register all tools
from tools import (
    register_multiplication_tool,
    register_temperature_converter_tool,
    register_weather_tools
)

register_multiplication_tool(mcp)
register_temperature_converter_tool(mcp)
register_weather_tools(mcp)

# CORS middleware
custom_middleware = [
    Middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
]

mcp_app = mcp.http_app(path='/mcp', middleware=custom_middleware)

app = FastAPI(
    title="JSON Environment API Key Protected MCP Server",
    description="MCP server with JSON environment variable API key authentication",
    version="1.0.0",
    lifespan=mcp_app.lifespan
)

# Middleware to protect MCP endpoints
@app.middleware("http")
async def api_key_middleware(request, call_next):
    """Middleware to protect MCP endpoints with API key"""
    
    # Skip auth for health and root endpoints
    skip_paths = ["/health", "/"]
    
    # Enable admin endpoints if explicitly enabled
    if os.environ.get('ENABLE_ADMIN_ENDPOINTS', 'false').lower() == 'true':
        skip_paths.extend(["/admin"])
    
    if any(request.url.path.startswith(path) for path in skip_paths):
        return await call_next(request)
    
    # Check API key for MCP endpoints
    if request.url.path.startswith("/mcp-server"):
        api_key = request.headers.get("X-API-Key")
        if not api_key:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="X-API-Key header required"
            )
        
        # Verify using pandas lookup
        try:
            client_info = verify_api_key(api_key)
            request.state.client_info = client_info
        except HTTPException:
            raise
    
    return await call_next(request)

# Mount protected MCP app
app.mount("/mcp-server", mcp_app)

@app.get("/")
async def root():
    active_count = len(get_active_keys())
    total_count = len(API_KEYS) if not API_KEYS.empty else 0
    
    return {
        "message": "JSON Environment API Key Protected MCP Server",
        "mcp_endpoint": "/mcp-server/mcp", 
        "authentication": "X-API-Key header required",
        "active_clients": active_count,
        "total_clients": total_count,
        "admin_enabled": os.environ.get('ENABLE_ADMIN_ENDPOINTS', 'false').lower() == 'true',
        "tools": [
            "multiply",
            "celsius_to_fahrenheit",
            "fahrenheit_to_celsius", 
            "get_alerts",
            "get_forecast"
        ]
    }

@app.get("/health")
async def health():
    active_count = len(get_active_keys())
    total_count = len(API_KEYS) if not API_KEYS.empty else 0
    
    return {
        "status": "healthy", 
        "active_keys": active_count,
        "total_keys": total_count,
        "keys_configured": not API_KEYS.empty
    }

# Admin endpoints (only enabled if environment variable is set)
@app.post("/admin/generate-key")
async def generate_api_key(ctf_name: str, read: bool = True, write: bool = True):
    """Generate new API key for a CTF lab (admin only)"""
    if os.environ.get('ENABLE_ADMIN_ENDPOINTS', 'false').lower() != 'true':
        raise HTTPException(status_code=404, detail="Admin endpoints disabled")
    
    new_key = add_api_key(ctf_name, read, write)
    
    return {
        "api_key": new_key,
        "ctf_name": ctf_name,
        "permissions": {"read": read, "write": write},
        "message": "Store this key securely - it won't be shown again",
        "note": "This key is only stored in memory. Update your API_KEYS_JSON environment variable to persist it."
    }

@app.get("/admin/list-keys")
async def list_api_keys():
    """List all API keys with their status (admin only)"""
    if os.environ.get('ENABLE_ADMIN_ENDPOINTS', 'false').lower() != 'true':
        raise HTTPException(status_code=404, detail="Admin endpoints disabled")
    
    if API_KEYS.empty:
        return {"message": "No API keys configured", "api_keys": []}
    
    # Don't show full API keys for security
    safe_keys = API_KEYS.copy()
    safe_keys['API_KEY'] = safe_keys['API_KEY'].apply(lambda x: f"{x[:8]}...{x[-4:]}" if len(x) > 12 else "***")
    
    return {
        "api_keys": safe_keys.to_dict('records'),
        "total_keys": len(API_KEYS),
        "active_keys": len(get_active_keys())
    }

@app.get("/admin/export-json")
async def export_api_keys_json():
    """Export current API keys as JSON for environment variable (admin only)"""
    if os.environ.get('ENABLE_ADMIN_ENDPOINTS', 'false').lower() != 'true':
        raise HTTPException(status_code=404, detail="Admin endpoints disabled")
    
    if API_KEYS.empty:
        return {"message": "No API keys to export", "json": "[]"}
    
    # Convert DataFrame to JSON string
    json_string = API_KEYS.to_json(orient='records', indent=2)
    
    return {
        "message": "Copy this JSON to your API_KEYS_JSON environment variable",
        "json": json_string,
        "formatted": json.loads(json_string)  # Pretty formatted version
    }

# Startup event to initialize keys
@app.on_event("startup")
async def startup_event():
    """Initialize API keys on startup"""
    initialize_api_keys()

if __name__ == "__main__":
    import uvicorn
    
    port = int(os.environ.get("PORT", "8000"))
    
    uvicorn.run(
        "main:app",
        host="0.0.0.0", 
        port=port,
        reload=True if os.environ.get("ENVIRONMENT") == "development" else False
    )