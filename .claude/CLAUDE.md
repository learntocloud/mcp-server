# Claude Context for MCP Server Project

This document provides important context for AI assistants working on this MCP (Model Context Protocol) server implementation.

## Project Overview

This is a Python/FastAPI implementation of an MCP server designed for deployment to Azure App Service. The server provides tools for multiplication, temperature conversion, and weather data retrieval.

## Key Architecture Decisions

### MCP Endpoint Path

- The MCP endpoint is mounted at `/mcp-server/mcp` (not `/mcp/`)
- This is because the FastMCP app is created with path `/mcp` but mounted under `/mcp-server`
- When connecting clients, always use the full path: `https://<host>/mcp-server/mcp`

### Transport Type

- Uses HTTP transport with Server-Sent Events (SSE) for streaming
- Transport type in MCP clients should be set to "streamable-http"
- No authentication is currently implemented (public endpoint)

### Framework Choice

- FastAPI for the web framework
- FastMCP for MCP protocol implementation
- Gunicorn with Uvicorn workers for production deployment

## Project Structure

```plain
/
├── src/
│   ├── main.py              # Main application entry point
│   ├── requirements.txt     # Python dependencies
│   └── tools/              # MCP tool implementations
│       ├── __init__.py
│       ├── multiplication_tool.py
│       ├── temperature_converter_tool.py
│       └── weather_tools.py
├── infra/                  # Azure infrastructure as code
│   ├── main.bicep
│   ├── main.parameters.json
│   └── resources.bicep
├── azure.yaml              # Azure Developer CLI configuration
└── README.md              # User-facing documentation
```

## Important Implementation Details

### Available Tools

1. `multiply` - Multiplies two numbers (parameters: a, b)
2. `celsius_to_fahrenheit` - Temperature conversion (parameter: celsius)
3. `fahrenheit_to_celsius` - Temperature conversion (parameter: fahrenheit)
4. `get_alerts` - US weather alerts by state (parameter: state)
5. `get_forecast` - Weather forecast by coordinates (parameters: lat, lon)

### CORS Configuration

- Currently allows all origins (`*`) for development flexibility
- Should be restricted in production environments

## Common Tasks

### Adding New Tools

1. Create a new file in `src/tools/` directory
2. Implement the tool registration function
3. Import and register in `main.py`
4. Follow the existing pattern from other tools

### Testing Locally

```bash
cd src
uvicorn main:app --reload
```

Then connect with MCP Inspector to `http://localhost:8000/mcp-server/mcp`

### Debugging Connection Issues

1. Check the endpoint URL includes `/mcp-server/mcp`
2. Verify transport type is "streamable-http"
3. Check CORS headers if connecting from a browser
4. Review Azure App Service logs for server errors

## Azure Deployment Notes

### Deployment Command

From the project root directory, use the Azure Developer CLI to deploy:

```bash
azd up
```

### Post-Deployment Verification

1. Check health endpoint: `https://<app-name>.azurewebsites.net/health`
2. Check root endpoint: `https://<app-name>.azurewebsites.net/`
3. Test MCP connection: `https://<app-name>.azurewebsites.net/mcp-server/mcp`

## Security Considerations

- No authentication is currently implemented
- All endpoints are publicly accessible
- Consider implementing API key or OAuth2 authentication for production
- CORS is currently wide open and should be restricted

## Common Pitfalls

1. **Wrong endpoint path**: Remember it's `/mcp-server/mcp`, not `/mcp/`
2. **Port conflicts**: Use PORT=8000 if 5000 is taken on macOS
3. **Missing dependencies**: Always install from requirements.txt
4. **CORS issues**: Check browser console for CORS errors
5. **Transport type**: Must be "streamable-http", not "http"
