#!/usr/bin/env python3
"""Ultra minimal test"""

print("Python is working")

try:
    import mcp
    print("MCP imported successfully")
except ImportError as e:
    print(f"MCP import failed: {e}")

try:
    from mcp.server import Server
    print("MCP Server imported successfully")
except ImportError as e:
    print(f"MCP Server import failed: {e}")

print("Basic test complete")