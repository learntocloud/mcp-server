# MCP Server - FastAPI on Azure App Service

This is a Python implementation of the MCP (Model Context Protocol) server using FastAPI and deployed to Azure App Service, providing multiplication, temperature conversion, and weather tools.

## 🎯 For CTF Users (Quick Start)

### Get Your API Key

Register for an API key with one simple command:

```bash
curl -X POST https://your-mcp-server.azurewebsites.net/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "your@email.com",
    "project_name": "My CTF Solution",
    "github_repo": "yourusername/your-ctf-fork"
  }'
```

**Response:**
```json
{
  "api_key": "sk_a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6",
  "message": "API key created successfully! Save this key securely - it won't be shown again.",
  "rate_limit": "1000 requests/hour",
  "created": "2024-01-15T10:30:00Z"
}
```

⚠️ **Important:** Save your API key securely! It won't be shown again.

### Use Your API Key

```bash
# Test the connection
curl -X POST https://your-mcp-server.azurewebsites.net/mcp-server/mcp/ \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -H "Authorization: Bearer sk_your_api_key_here" \
  -d '{"jsonrpc":"2.0","method":"tools/list","id":1}'

# Call a tool
curl -X POST https://your-mcp-server.azurewebsites.net/mcp-server/mcp/ \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -H "Authorization: Bearer sk_your_api_key_here" \
  -d '{
    "jsonrpc": "2.0",
    "method": "tools/call",
    "params": {
      "name": "multiply",
      "arguments": {"a": 5, "b": 10}
    },
    "id": 1
  }'
```

### Rate Limits
- **Registration:** 5 API keys per email per 24 hours
- **API Usage:** 1000 requests per hour per API key

### For Terraform/Infrastructure

```bash
# Get API key in your deployment script
API_KEY=$(curl -s -X POST https://your-mcp-server.azurewebsites.net/register \
  -H "Content-Type: application/json" \
  -d '{"email":"your@email.com","project_name":"CTF Infrastructure"}' \
  | jq -r '.api_key')

# Use in your scripts
export MCP_API_KEY="$API_KEY"
```

## 🛠️ For Server Administrators

### Manage API Keys

Use the admin tool to monitor and manage all API keys:

```bash
# List all API keys and registrations
python manage_api_keys.py list

# View details of a specific key
python manage_api_keys.py show sk_a1b2c3d4e5f6...

# Deactivate a compromised or abusive key
python manage_api_keys.py deactivate sk_a1b2c3d4e5f6...

# Reactivate a key
python manage_api_keys.py activate sk_a1b2c3d4e5f6...

# Create admin/service keys (bypass registration)
python manage_api_keys.py create "Admin monitoring key"

# Delete a key permanently
python manage_api_keys.py delete sk_a1b2c3d4e5f6...
```

### Monitor Registrations

```bash
# View registration statistics
python manage_api_keys.py registration-stats

# List all self-registrations
python manage_api_keys.py list-registrations
```

## 🧰 Available Tools

- **`multiply`** - Multiply two numbers
- **`celsius_to_fahrenheit`** - Convert Celsius to Fahrenheit
- **`fahrenheit_to_celsius`** - Convert Fahrenheit to Celsius
- **`get_alerts`** - Get US weather alerts by state
- **`get_forecast`** - Get weather forecast by coordinates

## 🏗️ Local Development

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

2. **Install dependencies:**

```bash
uv pip install -r requirements.txt
```

3. **Run the development server:**

```bash
# For local testing without authentication
uvicorn main:app --reload

# For testing with fallback token authentication
MCP_AUTH_TOKEN="test_token_local_dev" uvicorn main:app --reload
```

The server will start on `http://localhost:8000` by default.

### API Endpoints

- `/` - Root endpoint showing server status
- `/health` - Health check endpoint
- `/register` - Public API key registration
- `/register/info` - Registration information and examples
- `/mcp-server/mcp/` - MCP server endpoint for tool interactions

### Testing Registration Locally

```bash
# Test registration
curl -X POST http://localhost:8000/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "project_name": "Local Test",
    "github_repo": "testuser/test-repo"
  }'

# Test the returned API key
curl -X POST http://localhost:8000/mcp-server/mcp/ \
  -H "Authorization: Bearer sk_your_returned_key" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","method":"tools/list","id":1}'
```

### Testing with MCP Inspector

1. **Start the server** (if not already running):

```bash
uvicorn main:app --reload
```

2. **Run MCP Inspector:**

```bash
npx @modelcontextprotocol/inspector
```

3. **Connect to the MCP Server:**
   - **Transport Type**: streamable-http
   - **URL**: `http://localhost:8000/mcp-server/mcp/`
   - **Headers**: Add `Authorization: Bearer sk_your_api_key_here`

## ☁️ Azure Deployment

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

2. **Deploy using Azure Developer CLI:**

```bash
# From the project root directory
azd up
```

This will:

- Create a new resource group
- Deploy an App Service Plan (Linux)
- Deploy the Python web app with authentication enabled
- Create Azure Storage Account for API key management
- Configure Managed Identity for secure access
- Set up all necessary environment variables

### Post-Deployment

After deployment:

1. **Check the application health:** `https://<your-app>.azurewebsites.net/health`
2. **View available tools:** `https://<your-app>.azurewebsites.net/`
3. **Test registration:** `https://<your-app>.azurewebsites.net/register`
4. **Monitor logs** in Azure Portal or using Azure CLI

The MCP endpoint will be available at:
```
https://<your-app>.azurewebsites.net/mcp-server/mcp/
```

## 🔐 Authentication Architecture

### Production (Azure Storage)
- **Registration**: Public `/register` endpoint with rate limiting
- **Storage**: API keys stored in Azure Table Storage
- **Authentication**: Uses Azure Managed Identity
- **Rate Limiting**: 5 registrations per email per 24 hours, 1000 API calls per hour

### Development (Fallback Mode)
- **Fallback Token**: Set `MCP_AUTH_TOKEN` environment variable
- **Self-Registered Keys**: Accepts any properly formatted `sk_` keys
- **No Storage**: Works without Azure Storage for local testing

### Security Features
- ✅ **No hardcoded secrets** - Uses Azure Managed Identity
- ✅ **Rate limiting** - Prevents abuse at registration and API levels
- ✅ **API key lifecycle** - Activate/deactivate without deletion
- ✅ **Usage tracking** - Monitor API key usage patterns
- ✅ **Audit logging** - Comprehensive logging of auth attempts
- ✅ **JSONRPC compliance** - Proper error formats for MCP clients

## 🚨 Troubleshooting

### Registration Issues

**"Rate limit exceeded"**
- You've registered too many times with the same email
- Wait 24 hours or use a different email

**"Invalid email format"**
- Check your email address format
- Ensure it follows: user@domain.com

### Authentication Issues

**"Missing authorization header"**
- Include `Authorization: Bearer sk_your_key` header
- Check that your API key starts with `sk_`

**"Invalid authentication token"**
- Verify your API key is correct
- Check if the key has been deactivated
- Ensure the key hasn't expired (if expiration is enabled)

### Azure Deployment Issues

**Check logs:**
```bash
az webapp log tail --name <app-name> --resource-group <rg-name>
```

**SSH into container:**
```bash
az webapp ssh --name <app-name> --resource-group <rg-name>
```

**Restart app:**
```bash
az webapp restart --name <app-name> --resource-group <rg-name>
```

## 🔗 Integration Examples

### Python
```python
import requests

API_KEY = "sk_your_api_key_here"
MCP_URL = "https://your-server.azurewebsites.net/mcp-server/mcp/"

def call_mcp_tool(tool_name, arguments):
    response = requests.post(MCP_URL, 
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            "Authorization": f"Bearer {API_KEY}"
        },
        json={
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {
                "name": tool_name,
                "arguments": arguments
            },
            "id": 1
        }
    )
    return response.json()

# Use it
result = call_mcp_tool("multiply", {"a": 5, "b": 10})
print(result)
```

### JavaScript
```javascript
const API_KEY = "sk_your_api_key_here";
const MCP_URL = "https://your-server.azurewebsites.net/mcp-server/mcp/";

async function callMCPTool(toolName, arguments) {
    const response = await fetch(MCP_URL, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Accept': 'application/json, text/event-stream',
            'Authorization': `Bearer ${API_KEY}`
        },
        body: JSON.stringify({
            jsonrpc: '2.0',
            method: 'tools/call',
            params: {
                name: toolName,
                arguments: arguments
            },
            id: 1
        })
    });
    
    return response.json();
}

// Use it
callMCPTool('multiply', {a: 5, b: 10})
    .then(result => console.log(result));
```

### Terraform
```hcl
# Get API key
resource "null_resource" "get_api_key" {
  provisioner "local-exec" {
    command = <<-EOT
      API_KEY=$(curl -s -X POST https://your-server.azurewebsites.net/register \
        -H "Content-Type: application/json" \
        -d '{"email":"${var.admin_email}","project_name":"${var.project_name}"}' \
        | jq -r '.api_key')
      echo $API_KEY > ${path.module}/api_key.txt
    EOT
  }
}

# Use the API key
data "local_file" "api_key" {
  filename = "${path.module}/api_key.txt"
  depends_on = [null_resource.get_api_key]
}
```

## 📚 Resources

- [Azure Developer CLI Documentation](https://learn.microsoft.com/en-us/azure/developer/azd/)
- [FastAPI Documentation](https://fastapi.tiangolo.com/)
- [MCP Protocol Documentation](https://modelcontextprotocol.org/)
- [Uvicorn Documentation](https://www.uvicorn.org/)
- [MCP Inspector Documentation](https://modelcontextprotocol.org/inspector/)
- [Azure App Service Documentation](https://learn.microsoft.com/en-us/azure/app-service/)
- [FastMCP Documentation](https://fastmcp.org/)
- [Authentication Guide](./AUTHENTICATION.md)
- [CTF Setup Guide](./CTF_SETUP.md)

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.