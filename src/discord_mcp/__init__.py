"""Discord OAuth2 integration for Model Context Protocol."""

from . import server
import asyncio
import tracemalloc

__version__ = "0.1.0"

def main():
    """Main entry point for the OAuth2 Discord MCP server."""
    # Enable tracemalloc for better debugging
    tracemalloc.start()

    try:
        # Properly handle async execution
        asyncio.run(server.main())
    except KeyboardInterrupt:
        print("\nShutting down Discord MCP OAuth2 server...")
    except Exception as e:
        print(f"Error running Discord MCP OAuth2 server: {e}")
        raise

# Expose important items at package level
__all__ = ['main', 'server']
