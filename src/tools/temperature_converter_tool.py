from fastmcp import FastMCP

def register_temperature_converter_tool(mcp: FastMCP):
    """Register temperature converter tools with the MCP server"""
    
    @mcp.tool()
    def celsius_to_fahrenheit(celsius: float) -> float:
        """Convert Celsius to Fahrenheit"""
        return (celsius * 9/5) + 32
    
    @mcp.tool()
    def fahrenheit_to_celsius(fahrenheit: float) -> float:
        """Convert Fahrenheit to Celsius"""
        return (fahrenheit - 32) * 5/9