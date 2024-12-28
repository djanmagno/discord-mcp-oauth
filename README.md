# Discord MCP Server

A Model Context Protocol (MCP) server that provides Discord integration capabilities to MCP clients like Claude Desktop.

## Available Tools

### Server Information
- `get_server_info`: Get detailed server information
- `list_members`: List server members and their roles

### Message Management
- `send_message`: Send a message to a channel
- `read_messages`: Read recent message history
- `add_reaction`: Add a reaction to a message
- `remove_reaction`: Remove a reaction from a message
- `moderate_message`: Delete messages and timeout users

### Channel Management
- `create_text_channel`: Create a new text channel
- `delete_channel`: Delete an existing channel

### Role Management
- `add_role`: Add a role to a user
- `remove_role`: Remove a role from a user

### Webhook Management
- `create_webhook`: Create a new webhook
- `list_webhooks`: List webhooks in a channel
- `send_webhook_message`: Send messages via webhook
- `modify_webhook`: Update webhook settings
- `delete_webhook`: Delete a webhook

## Installation

1. Set up your Discord bot:
   - Create a new application at [Discord Developer Portal](https://discord.com/developers/applications)
   - Create a bot and copy the token
   - Enable required privileged intents:
     - MESSAGE CONTENT INTENT
     - PRESENCE INTENT
     - SERVER MEMBERS INTENT
   - Invite the bot to your server using OAuth2 URL Generator

2. Clone and install the package:
```bash
# Clone the repository
git clone https://github.com/hanweg/mcp-discord.git
cd mcp-discord

# Create and activate virtual environment
uv venv
.venv\Scripts\activate  # On Windows
source .venv/bin/activate  # On macOS/Linux

# Install the package
uv pip install -e .
```

3. Configure Claude Desktop (`%APPDATA%\Claude\claude_desktop_config.json` on Windows, `~/Library/Application Support/Claude/claude_desktop_config.json` on macOS):
```json
{
  "mcpServers": {
    "discord": {
      "command": "uv",
      "args": [
        "--directory",
        "path/to/mcp-discord",
        "run",
        "discord_mcp.server"
      ],
      "env": {
        "DISCORD_TOKEN": "your_bot_token_here"
      }
    }
  }
}
```

## License

MIT License - see LICENSE file for details.
