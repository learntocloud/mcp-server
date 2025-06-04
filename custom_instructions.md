# GitHub Copilot Custom Instructions - MCP Server Project

## Project Context

This is a Python-based MCP (Model Context Protocol) server implementation using FastAPI, deployed on Azure App Service. The server provides mathematical computation, temperature conversion, and weather data tools accessible via the MCP protocol. **The server includes a production-ready authentication system with self-service API key registration designed for open-source CTF deployments.**

## Core Technologies & Frameworks

- **Python 3.11+** with type hints (required)
- **FastAPI** for REST API and web server functionality
- **FastMCP** for MCP protocol implementation and tool registration
- **Uvicorn** with Gunicorn for production deployment
- **Azure App Service** for cloud hosting with managed identity
- **Azure Table Storage** for API key and registration management
- **Azure Bicep** for Infrastructure as Code (IaC)

## Project Architecture & Structure

```plain
src/
├── main.py                     # Application entry point & FastAPI setup
├── auth.py                     # Authentication middleware and API key validation  
├── registration.py             # Self-service API key registration system
├── requirements.txt            # Python dependencies
└── tools/                     # MCP tool implementations
    ├── __init__.py            # Tool exports
    ├── multiplication_tool.py  # Math operations
    ├── temperature_converter_tool.py
    └── weather_tools.py       # External API integrations

manage_api_keys.py             # CLI tool for API key and registration management
infra/                         # Azure deployment infrastructure
├── main.bicep
├── main.parameters.json
└── resources.bicep

azure.yaml                     # Azure Developer CLI config
CLAUDE.md                      # Authentication context for AI agents
AUTHENTICATION.md              # Detailed auth documentation
CTF_SETUP.md                   # CTF user guide
```

## Critical Implementation Patterns

### MCP Tool Registration Pattern

Always follow this exact pattern when creating new MCP tools:

```python
from fastmcp import FastMCP

def register_[tool_name]_tool(mcp: FastMCP):
    """Register [tool_name] tool with the MCP server"""
    
    @mcp.tool()
    def tool_function(param: type) -> return_type:
        """Clear description of what the tool does"""
        # Implementation here
        return result
```

### Authentication Middleware Pattern

**CRITICAL**: The app uses authentication middleware that must be preserved:

```python
from auth import TokenAuthMiddleware

custom_middleware = [
    Middleware(TokenAuthMiddleware),    # Auth MUST be first
    Middleware(CORSMiddleware, ...)     # CORS after auth
]

mcp_app = mcp.http_app(path='/mcp', middleware=custom_middleware)
```

### FastAPI App Structure

The app uses a specific mounting pattern with authentication:

- MCP app is created with path `/mcp` and custom middleware
- Mounted on main app at `/mcp-server`
- Final MCP endpoint: `/mcp-server/mcp/` (note trailing slash)
- Authentication endpoints: `/register` and `/register/info`
- Never change this path structure or middleware order

### Required Imports in main.py

```python
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware import Middleware
from fastmcp import FastMCP
from auth import TokenAuthMiddleware
from registration import (
    RegistrationRequest, 
    RegistrationResponse,
    registration_manager
)
from tools import (register_*_tool functions)
```

## Code Style & Standards

### Type Hints

- **ALWAYS** use type hints for all function parameters and return values
- Use `float` for numeric calculations (not `int` unless specifically integers)
- Use proper typing imports: `from typing import List, Dict, Optional`

### Error Handling

- Use FastAPI's HTTPException for API errors
- Implement proper error responses for MCP tools
- Always validate inputs before processing

### Documentation

- Every tool function must have a clear docstring
- Use triple quotes for docstrings
- Keep descriptions concise but informative

## Specific Project Rules

### 1. MCP Tool Development

- New tools go in `src/tools/` directory
- Each tool gets its own Python file
- Export registration function in `__init__.py`
- Import and register in `main.py`

### 2. Endpoint Structure

- Root endpoint (`/`) shows server status and available tools (no auth)
- Health endpoint (`/health`) for Azure monitoring (no auth)
- Registration endpoint (`/register`) for self-service API keys (no auth) 
- Registration info (`/register/info`) for documentation (no auth)
- MCP endpoint at `/mcp-server/mcp/` (requires authentication)
- Never change these paths or authentication requirements

### 3. CORS Configuration

```python
custom_middleware = [
    Middleware(
        CORSMiddleware,
        allow_origins=["*"],  # Restrict in production
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
]
```

### 4. Environment Variables

**Authentication & Storage:**
- `AZURE_STORAGE_ACCOUNT_NAME`: Storage account for API keys (production)
- `AZURE_STORAGE_CONNECTION_STRING`: Connection string (development)
- `MCP_AUTH_TOKEN`: Fallback token (development/testing)

**Rate Limiting:**
- `REGISTRATION_RATE_LIMIT`: Max registrations per email per day (default: 5)
- `REGISTRATION_WINDOW_HOURS`: Rate limit window (default: 24)
- `RATE_LIMIT_REQUESTS`: API calls per hour per key (default: 1000)

**Server:**
- `PORT`: Server port (default: 8000)
- `ENVIRONMENT`: Development vs production logic

## Development & Testing Guidelines

### Local Development Commands

```bash
cd src

# Without authentication (fallback mode)
uvicorn main:app --reload

# With fallback token authentication  
MCP_AUTH_TOKEN="test_token_local_dev" uvicorn main:app --reload

# Test registration
curl -X POST http://localhost:8000/register \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","project_name":"Local Test"}'
```

### Testing with MCP Inspector

- Transport Type: "streamable-http"
- URL: `http://localhost:8000/mcp-server/mcp/` (note trailing slash)
- Headers: Add `Authorization: Bearer sk_your_api_key_here`
- Get API key from `/register` endpoint first

### Azure Deployment

```bash
azd up  # Deploy entire stack
```

## Common Patterns to Follow

### Adding External API Tools

When creating tools that call external APIs:

1. Use `httpx` for HTTP requests (already in requirements.txt)
2. Handle API errors gracefully
3. Add appropriate type hints for API responses
4. Consider rate limiting and error retry logic

### Tool Parameter Validation

```python
@mcp.tool()
def example_tool(param: str) -> str:
    """Tool description"""
    if not param or param.strip() == "":
        raise ValueError("Parameter cannot be empty")
    # Process and return
```

## Security & Authentication

**CRITICAL - Authentication is ALWAYS required for MCP endpoints:**

- **Public Endpoints**: `/`, `/health`, `/register`, `/register/info`
- **Protected Endpoints**: `/mcp-server/mcp/` (requires `Authorization: Bearer sk_...`)
- **Rate Limiting**: Registration (5/day/email) and API usage (1000/hour/key)
- **Azure Security**: Uses Managed Identity, no hardcoded secrets
- **Privacy**: Email addresses are hashed before storage

**Never disable authentication or modify middleware order**

## Avoid These Common Mistakes

1. **Wrong MCP endpoint path** - Must be `/mcp-server/mcp/` (with trailing slash)
2. **Breaking authentication** - Never modify middleware order or disable auth
3. **Missing Authorization header** - Must be `Authorization: Bearer sk_...`
4. **Missing type hints** - Always include them
5. **Not registering new tools** - Update `__init__.py` and `main.py`
6. **Incorrect FastMCP usage** - Follow the exact @mcp.tool() decorator pattern
7. **Breaking CORS or middleware** - Keep configuration intact
8. **Hardcoding secrets** - Use environment variables only
9. **Ignoring rate limits** - Respect registration and API usage limits

## Dependencies Management

- Keep `requirements.txt` minimal and specific
- Pin major versions for stability
- Current key dependencies:
  - `fastmcp>=2.3.2`
  - `fastapi>=0.115.0`
  - `uvicorn[standard]>=0.32.0`
  - `httpx>=0.27.0`
  - `azure-data-tables>=12.6.0`
  - `azure-identity>=1.18.0`

## Azure-Specific Patterns

- Use Azure Bicep for infrastructure with managed identity
- Azure Table Storage for API keys (`apikeys`) and registrations (`registrations`) 
- Follow Azure App Service Python best practices
- Configure proper startup commands in deployment
- Use Azure Developer CLI (`azd`) for deployment workflow
- Storage Account requires "Storage Table Data Contributor" role for App Service

## Administrative Commands

```bash
# API key management (on server or with Azure credentials)
python manage_api_keys.py list                    # View all keys
python manage_api_keys.py list-registrations      # View self-registrations  
python manage_api_keys.py registration-stats      # Registration statistics
python manage_api_keys.py create "Admin key"      # Create admin key
python manage_api_keys.py deactivate sk_bad_key   # Disable abusive key
```

When suggesting code changes or new features, always:

1. Follow the established project structure
2. Maintain the MCP tool registration pattern  
3. **Preserve authentication middleware and registration system**
4. Keep the FastAPI mounting configuration intact
5. Add proper type hints and documentation
6. Consider Azure deployment and security implications
7. **Never suggest removing or bypassing authentication**
