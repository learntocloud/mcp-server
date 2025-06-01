import httpx
from fastmcp import FastMCP

def register_weather_tools(mcp: FastMCP):
    """Register weather tools with the MCP server"""
    
    @mcp.tool()
    async def get_alerts(state: str) -> str:
        """Get weather alerts for a US state"""
        async with httpx.AsyncClient() as client:
            client.headers.update({
                "User-Agent": "(mcp-server, example@example.com)"
            })
            try:
                response = await client.get(
                    f"https://api.weather.gov/alerts/active?area={state.upper()}"
                )
                response.raise_for_status()
                
                data = response.json()
                features = data.get("features", [])
                
                if not features:
                    return f"No active alerts for {state}"
                
                alerts = []
                for feature in features[:5]:  # Limit to 5 alerts
                    props = feature.get("properties", {})
                    alerts.append(
                        f"- {props.get('headline', 'Unknown alert')}\n"
                        f"  Severity: {props.get('severity', 'Unknown')}\n"
                        f"  Areas: {', '.join(props.get('areaDesc', '').split('; ')[:3])}"
                    )
                
                return f"Active alerts for {state}:\n" + "\n".join(alerts)
                
            except httpx.HTTPStatusError as e:
                return f"Error fetching alerts: HTTP {e.response.status_code}"
            except Exception as e:
                return f"Error fetching alerts: {str(e)}"
    
    @mcp.tool()
    async def get_forecast(latitude: float, longitude: float) -> str:
        """Get weather forecast for coordinates"""
        async with httpx.AsyncClient() as client:
            client.headers.update({
                "User-Agent": "(mcp-server, example@example.com)"
            })
            try:
                # First, get the forecast URL from the point
                point_response = await client.get(
                    f"https://api.weather.gov/points/{latitude},{longitude}"
                )
                point_response.raise_for_status()
                
                point_data = point_response.json()
                forecast_url = point_data["properties"]["forecast"]
                
                # Now get the actual forecast
                forecast_response = await client.get(forecast_url)
                forecast_response.raise_for_status()
                
                forecast_data = forecast_response.json()
                periods = forecast_data["properties"]["periods"]
                
                if not periods:
                    return "No forecast data available"
                
                # Format the forecast for the next few periods
                forecast_text = f"Forecast for coordinates ({latitude}, {longitude}):\n"
                for period in periods[:4]:  # Show next 4 periods
                    forecast_text += f"\n{period['name']}:\n"
                    forecast_text += f"  {period['detailedForecast']}\n"
                    forecast_text += f"  Temperature: {period['temperature']}°{period['temperatureUnit']}\n"
                
                return forecast_text
                
            except httpx.HTTPStatusError as e:
                return f"Error fetching forecast: HTTP {e.response.status_code}"
            except KeyError as e:
                return f"Error parsing weather data: Missing field {str(e)}"
            except Exception as e:
                return f"Error fetching forecast: {str(e)}"