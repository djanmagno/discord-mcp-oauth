#!/usr/bin/env python3
import json
import sys
import asyncio
from discord_mcp.server import app, list_tools

async def test_mcp():
    """Test MCP server response"""
    print("Testing MCP server...")

    # Test that our tools are available
    try:
        tools = await list_tools()
        print(f"✅ Found {len(tools)} tools:")
        for tool in tools:
            print(f"  - {tool.name}: {tool.description}")
    except Exception as e:
        print(f"❌ Error: {e}")

if __name__ == "__main__":
    asyncio.run(test_mcp())