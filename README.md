# MCP Server - FastAPI on Azure App Service

This is a Python implementation of the MCP (Model Context Protocol) server using FastAPI and deployed to Azure App Service, providing multiplication, temperature conversion, and weather tools.

## Features

- **Multiplication Tool**: Multiply two numbers
- **Temperature Converter Tools**: Convert between Celsius and Fahrenheit
- **Weather Tools**: Get US weather alerts by state and forecasts by coordinates

## Local Development

### Prerequisites

- Python 3.11+
- [uv](https://github.com/astral-sh/uv) for faster dependency management and virtual environment creation
- Node.js & npm (for running MCP Inspector)

### Setup and Running

1. **Create a virtual environment:**

```bash
cd src
uv venv
# Activate the virtual environment
source .venv/bin/activate  # On macOS/Linux
# OR
.venv\Scripts\activate     # On Windows
```

1. **Install dependencies:**

```bash
uv pip install -r requirements.txt
```

1. **Run the development server with auto-reload:**

```bash
uvicorn main:app --reload
```

The server will start on `http://localhost:8000` by default.

### API Endpoints

- `/` - Root endpoint showing server status
- `/health` - Health check endpoint
- `/mcp-server/mcp` - MCP server endpoint for tool interactions

### Testing with MCP Inspector

1. **Start the server** (if not already running):

```bash
uvicorn main:app --reload
```

1. **Run MCP Inspector:**

```bash
npx @modelcontextprotocol/inspector
```

1. **Connect to the MCP Server:**
   - **Transport Type**: streamable-http
   - **URL**: `http://localhost:8000/mcp-server/mcp`
   - **Authentication**: None

1. **Available Tools:**
   - `multiply` - Multiply two numbers
   - `celsius_to_fahrenheit` - Convert Celsius to Fahrenheit
   - `fahrenheit_to_celsius` - Convert Fahrenheit to Celsius
   - `get_alerts` - Get US weather alerts by state
   - `get_forecast` - Get weather forecast by coordinates

## Azure Deployment

### Azure Prerequisites

- Azure CLI installed (`az`)
- Azure Developer CLI installed (`azd`)
- Azure subscription

### Deployment Process

1. **Login to Azure:**

```bash
az login
azd auth login
```

1. **Deploy using Azure Developer CLI:**

```bash
# From the project root directory
azd up
```

This will:

- Create a new resource group
- Deploy an App Service Plan (Linux)
- Deploy the Python web app
- Configure all necessary settings

### Post-Deployment

After deployment:

1. Check the application health: `https://<your-app>.azurewebsites.net/health`
2. View available tools: `https://<your-app>.azurewebsites.net/`
3. Monitor logs in Azure Portal or using Azure CLI

### Connecting to the MCP Server

The MCP endpoint is available at:

```text
https://<your-app>.azurewebsites.net/mcp-server/mcp
```

To connect using MCP Inspector or other MCP clients:

1. Use the full URL: `https://<your-app>.azurewebsites.net/mcp-server/mcp`
2. Select "streamable-http" as the transport type
3. No authentication is currently required (the endpoint is publicly accessible)

## Security Considerations

- No authentication is currently implemented (public endpoints)
- CORS is wide open for development
- Consider implementing API key or OAuth2 authentication for production
- Validate all user inputs in tools to prevent injection attacks

### Troubleshooting

- Check logs: `az webapp log tail --name <app-name> --resource-group <rg-name>`
- SSH into container: `az webapp ssh --name <app-name> --resource-group <rg-name>`
- Restart app: `az webapp restart --name <app-name> --resource-group <rg-name>`

### Resources

- [Azure Developer CLI Documentation](https://learn.microsoft.com/en-us/azure/developer/azd/)
- [FastAPI Documentation](https://fastapi.tiangolo.com/)
- [MCP Protocol Documentation](https://modelcontextprotocol.org/)
- [Uvicorn Documentation](https://www.uvicorn.org/)
- [MCP Inspector Documentation](https://modelcontextprotocol.org/inspector/)
- [Azure App Service Documentation](https://learn.microsoft.com/en-us/azure/app-service/)
- [FastMCP Documentation](https://fastmcp.org/)
