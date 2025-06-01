from fastmcp import FastMCP

def register_multiplication_tool(mcp: FastMCP):
    """Register multiplication tool with the MCP server"""
    
    @mcp.tool()
    def multiply(a: float, b: float) -> float:
        """Multiply two numbers"""
        return a * b