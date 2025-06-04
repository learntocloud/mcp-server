import os
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware import Middleware
from fastmcp import FastMCP
from auth import TokenAuthMiddleware
from registration import (
    APIKeyRegistrationManager, 
    RegistrationRequest, 
    RegistrationResponse,
    registration_manager
)
from tools import (
    register_multiplication_tool,
    register_temperature_converter_tool,
    register_weather_tools
)

# Create MCP server instance
mcp = FastMCP(
    name="MCP Server",
    dependencies=["httpx", "fastapi", "uvicorn[standard]"]
)

# Register all tools
register_multiplication_tool(mcp)
register_temperature_converter_tool(mcp)
register_weather_tools(mcp)

# Define custom middleware with authentication and CORS
custom_middleware = [
    Middleware(TokenAuthMiddleware),  # Authentication always enabled
    Middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
]

# Get the MCP HTTP app with CORS middleware and custom path
mcp_app = mcp.http_app(path='/mcp', middleware=custom_middleware)

# Create FastAPI app with the MCP app's lifespan
app = FastAPI(
    title="MCP Server",
    description="Remote MCP server with multiplication, temperature conversion, and weather tools",
    version="1.0.0",
    lifespan=mcp_app.lifespan
)

# Mount the MCP app
app.mount("/mcp-server", mcp_app)

# Root endpoint
@app.get("/")
async def root():
    return {
        "message": "MCP Server is running",
        "mcp_endpoint": "/mcp-server/mcp",
        "tools": [
            "multiply",
            "celsius_to_fahrenheit",
            "fahrenheit_to_celsius",
            "get_alerts",
            "get_forecast"
        ]
    }

# Health check endpoint for Azure
@app.get("/health")
async def health():
    return {"status": "healthy"}

# API Key Registration endpoint
@app.post("/register", response_model=RegistrationResponse)
async def register_for_api_key(request: RegistrationRequest):
    """
    Register for an API key to access the MCP server.
    
    Rate limited to prevent abuse:
    - 5 registrations per email per 24 hours
    - Duplicate emails are rejected
    
    Example:
        curl -X POST https://your-server.com/register \\
          -H "Content-Type: application/json" \\
          -d '{
            "email": "user@example.com",
            "project_name": "My CTF Project",
            "github_repo": "username/my-ctf-fork"
          }'
    """
    try:
        return await registration_manager.create_registration(request)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail={
                "error": "Registration failed",
                "message": "An unexpected error occurred. Please try again later."
            }
        )

# Registration info endpoint
@app.get("/register/info")
async def registration_info():
    """Get information about the registration process."""
    return {
        "description": "Get an API key to access the MCP server",
        "rate_limit": "5 registrations per email per 24 hours",
        "key_format": "sk_[32_character_hex]",
        "usage_limit": "1000 requests per hour per key",
        "required_fields": ["email", "project_name"],
        "optional_fields": ["github_repo", "organization"],
        "example": {
            "email": "user@example.com",
            "project_name": "My CTF Project",
            "github_repo": "username/my-ctf-fork",
            "organization": "My University"
        }
    }

if __name__ == "__main__":
    import uvicorn
    
    # Get port from environment variable or default to 8000
    port = int(os.environ.get("PORT", "8000"))
    
    # Run with uvicorn
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=port,
        reload=True if os.environ.get("ENVIRONMENT") == "development" else False
    )