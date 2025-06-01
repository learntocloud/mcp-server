import os
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware import Middleware
from fastmcp import FastMCP
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

# Define custom middleware for CORS
custom_middleware = [
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