#!/usr/bin/env python3
"""Minimal Discord MCP server to test connection"""

import asyncio
import logging
import os
from typing import Any, List

from mcp.server import Server
from mcp.types import Tool, TextContent
from mcp.server.stdio import stdio_server

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/tmp/discord-simple-mcp.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("discord-simple-mcp")

# Initialize MCP server
app = Server("discord-simple")

@app.list_tools()
async def list_tools() -> List[Tool]:
    """List available tools."""
    logger.info("📋 Returning simple test tool")
    return [
        Tool(
            name="ping",
            description="Test if the Discord MCP server is responding",
            inputSchema={
                "type": "object",
                "properties": {},
                "required": []
            }
        )
    ]

@app.call_tool()
async def call_tool(name: str, arguments: Any) -> List[TextContent]:
    """Handle tool calls."""
    logger.info(f"📥 TOOL CALL: {name} with args: {arguments}")

    if name == "ping":
        logger.info("✅ Ping successful")
        return [TextContent(
            type="text",
            text="✅ Discord MCP server is responding! Connection successful."
        )]

    raise ValueError(f"Unknown tool: {name}")

async def main():
    """Main entry point."""
    logger.info("🚀 Starting Simple Discord MCP server")

    try:
        async with stdio_server() as (read_stream, write_stream):
            logger.info("📡 Simple MCP server ready")
            await app.run(
                read_stream,
                write_stream,
                app.create_initialization_options()
            )
    except Exception as e:
        logger.error(f"💥 Error: {e}")
        raise

if __name__ == "__main__":
    asyncio.run(main())