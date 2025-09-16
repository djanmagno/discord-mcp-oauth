#!/usr/bin/env python3
import asyncio
from discord_mcp.server import discord_client

async def test():
    try:
        guilds = await discord_client.get_user_guilds()
        print(f'Found {len(guilds)} servers:', [g['name'] for g in guilds])
    except Exception as e:
        print(f'Error: {e}')
    finally:
        await discord_client.close()

if __name__ == "__main__":
    asyncio.run(test())