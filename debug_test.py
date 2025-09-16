#!/usr/bin/env python3
import asyncio
import time
from datetime import datetime
from discord_mcp.server import discord_client, call_tool

async def debug_test():
    """Test the exact call that Claude Desktop makes"""
    print(f"🔍 Starting debug test at {datetime.now()}")

    try:
        print("📞 Calling list_servers tool...")
        start = time.time()

        result = await call_tool("list_servers", {})

        elapsed = time.time() - start
        print(f"✅ Tool completed in {elapsed:.2f} seconds")
        print(f"📋 Result: {result[0].text}")

    except Exception as e:
        elapsed = time.time() - start
        print(f"❌ Tool failed after {elapsed:.2f} seconds")
        print(f"💥 Error: {e}")

    finally:
        await discord_client.close()

if __name__ == "__main__":
    asyncio.run(debug_test())