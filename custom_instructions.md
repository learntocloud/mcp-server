# GitHub Copilot Custom Instructions - MCP Server Project

## Project Context

This is a Python-based MCP (Model Context Protocol) server implementation using FastAPI, deployed on Azure App Service. The server provides mathematical computation, temperature conversion, and weather data tools accessible via the MCP protocol.

## Core Technologies & Frameworks

- **Python 3.11+** with type hints (required)
- **FastAPI** for REST API and web server functionality
- **FastMCP** for MCP protocol implementation and tool registration
- **Uvicorn** with Gunicorn for production deployment
- **Azure App Service** for cloud hosting
- **Azure Bicep** for Infrastructure as Code (IaC)

## Project Architecture & Structure

```plain
src/
├── main.py                     # Application entry point & FastAPI setup
├── requirements.txt            # Python dependencies
└── tools/                     # MCP tool implementations
    ├── __init__.py            # Tool exports
    ├── multiplication_tool.py  # Math operations
    ├── temperature_converter_tool.py
    └── weather_tools.py       # External API integrations

infra/                         # Azure deployment infrastructure
├── main.bicep
├── main.parameters.json
└── resources.bicep

azure.yaml                     # Azure Developer CLI config
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

### FastAPI App Structure

The app uses a specific mounting pattern:

- MCP app is created with path `/mcp`
- Mounted on main app at `/mcp-server`
- Final MCP endpoint: `/mcp-server/mcp`
- Never change this path structure

### Required Imports in main.py

```python
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware import Middleware
from fastmcp import FastMCP
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

- Root endpoint (`/`) shows server status and available tools
- Health endpoint (`/health`) for Azure monitoring
- MCP endpoint at `/mcp-server/mcp` (never change this path)

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

- Use `PORT` environment variable (default: 8000)
- Use `ENVIRONMENT` for development vs production logic

## Development & Testing Guidelines

### Local Development Commands

```bash
cd src
uvicorn main:app --reload  # Development server
```

### Testing with MCP Inspector

- Transport Type: "streamable-http"
- URL: `http://localhost:8000/mcp-server/mcp`
- No authentication required

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

## Security Considerations

- No authentication currently implemented (public endpoints)
- CORS is wide open for development
- Consider API key auth for production tools
- Validate all user inputs in tools

## Avoid These Common Mistakes

1. **Wrong MCP endpoint path** - Must be `/mcp-server/mcp`
2. **Missing type hints** - Always include them
3. **Not registering new tools** - Update `__init__.py` and `main.py`
4. **Incorrect FastMCP usage** - Follow the exact @mcp.tool() decorator pattern
5. **Breaking CORS** - Keep middleware configuration intact
6. **Port conflicts** - Use PORT environment variable

## Dependencies Management

- Keep `requirements.txt` minimal and specific
- Pin major versions for stability
- Current key dependencies:
  - `fastmcp>=2.3.2`
  - `fastapi>=0.115.0`
  - `uvicorn[standard]>=0.32.0`
  - `httpx>=0.27.0`

## Azure-Specific Patterns

- Use Azure Bicep for infrastructure
- Follow Azure App Service Python best practices
- Configure proper startup commands in deployment
- Use Azure Developer CLI (`azd`) for deployment workflow

When suggesting code changes or new features, always:

1. Follow the established project structure
2. Maintain the MCP tool registration pattern
3. Keep the FastAPI mounting configuration intact
4. Add proper type hints and documentation
5. Consider Azure deployment implications
