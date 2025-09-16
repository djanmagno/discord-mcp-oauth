# Discord MCP OAuth2 Server

A Model Context Protocol (MCP) server that provides Discord integration using OAuth2 user authentication for MCP clients like Claude Desktop. This allows Claude to access Discord with YOUR permissions, eliminating the need for bot setup and admin approvals.

## Key Benefits

- ✅ **No Bot Required**: Use your own Discord account instead of creating a bot
- ✅ **Automatic Access**: Access all servers you're already a member of
- ✅ **No Admin Approval**: No need to get bot permissions from server administrators
- ✅ **Your Permissions**: Claude sees exactly what you can see on Discord
- ✅ **Secure**: OAuth2 with encrypted token storage and automatic refresh

## Available Tools

### Server Information
- `list_servers`: List all Discord servers you have access to
- `get_server_info`: Get detailed information about a server
- `get_channels`: List channels in a server you can see
- `list_members`: List server members (if you have permission)
- `get_user_info`: Get information about a Discord user

### Message Reading
- `read_messages`: Read recent message history from channels you can access

*Note: Write operations (sending messages, managing roles, etc.) are not included as they require special permissions that regular users typically don't have.*

## Installation

### 1. Set up Discord OAuth2 Application

1. Go to [Discord Developer Portal](https://discord.com/developers/applications)
2. Click "New Application" and give it a name
3. Navigate to **OAuth2** → **General**
4. Copy the **Client ID** and **Client Secret**
5. Add redirect URI: `http://localhost:8000/callback`
6. Save changes

### 2. Clone and Install

```bash
# Clone this repository
git clone https://github.com/YOUR-USERNAME/mcp-discord-oauth.git
cd mcp-discord-oauth

# Create and activate virtual environment
uv venv
source .venv/bin/activate  # macOS/Linux
# .venv\Scripts\activate   # Windows

# Install dependencies
uv pip install -e .
```

### 3. Configure Claude Desktop

Update your Claude Desktop configuration file:

**macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
**Windows**: `%APPDATA%\Claude\claude_desktop_config.json`

```json
{
  "mcpServers": {
    "discord": {
      "command": "uv",
      "args": [
        "--directory",
        "/path/to/mcp-discord-oauth",
        "run",
        "mcp-discord"
      ],
      "env": {
        "DISCORD_CLIENT_ID": "your_oauth_client_id",
        "DISCORD_CLIENT_SECRET": "your_oauth_client_secret",
        "DISCORD_REDIRECT_URI": "http://localhost:8000/callback"
      }
    }
  }
}
```

### 4. First Time Setup

1. Restart Claude Desktop
2. Try using a Discord command like "What servers do I have access to?"
3. Your browser will open for OAuth2 authorization
4. Grant permission to access your Discord account
5. Return to Claude - it now has access to your Discord data!

## How It Works

1. **OAuth2 Authentication**: Uses standard OAuth2 flow to authenticate with your Discord account
2. **Token Storage**: Securely stores access tokens with encryption in your home directory
3. **Auto Refresh**: Automatically refreshes tokens when they expire
4. **REST API**: Makes direct Discord API calls using your permissions
5. **MCP Integration**: Provides tools to Claude Desktop for Discord interaction

## Security

- Tokens are encrypted using Fernet symmetric encryption
- Stored in your home directory with restricted permissions
- Uses PKCE (Proof Key for Code Exchange) for additional security
- Automatic token refresh prevents stale credentials

## License

MIT License - see LICENSE file for details.
