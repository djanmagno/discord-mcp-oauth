import os
import sys
import asyncio
import logging
import json
import base64
import hashlib
import secrets
import webbrowser
from datetime import datetime, timedelta
from typing import Any, List, Dict, Optional
from functools import wraps
from urllib.parse import urlencode, parse_qs, urlparse
from pathlib import Path
from cryptography.fernet import Fernet
import aiohttp
from aiohttp import web
from mcp.server import Server
from mcp.types import Tool, TextContent
from mcp.server.stdio import stdio_server

def _configure_windows_stdout_encoding():
    if sys.platform == "win32":
        import io
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
        sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8')

_configure_windows_stdout_encoding()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/tmp/discord-mcp-server.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("discord-mcp-server")

# OAuth2 configuration
DISCORD_CLIENT_ID = os.getenv("DISCORD_CLIENT_ID")
DISCORD_CLIENT_SECRET = os.getenv("DISCORD_CLIENT_SECRET")
DISCORD_REDIRECT_URI = os.getenv("DISCORD_REDIRECT_URI", "http://localhost:8000/callback")

if not DISCORD_CLIENT_ID or not DISCORD_CLIENT_SECRET:
    raise ValueError("DISCORD_CLIENT_ID and DISCORD_CLIENT_SECRET environment variables are required")

# Discord API configuration
DISCORD_API_BASE = "https://discord.com/api/v10"
DISCORD_CDN_BASE = "https://cdn.discordapp.com"

# OAuth2 scopes
REQUIRED_SCOPES = ["identify", "guilds", "guilds.members.read", "messages.read"]

# Initialize MCP server
app = Server("discord-server")

# Store Discord client reference
discord_client = None

class TokenManager:
    def __init__(self):
        self.token_file = Path.home() / ".discord_mcp_tokens"
        self._encryption_key = self._get_or_create_key()
        self.fernet = Fernet(self._encryption_key)
        logger.info(f"🔑 Token file path: {self.token_file}")

    def _get_or_create_key(self) -> bytes:
        key_file = Path.home() / ".discord_mcp_key"
        if key_file.exists():
            return key_file.read_bytes()
        key = Fernet.generate_key()
        key_file.write_bytes(key)
        key_file.chmod(0o600)
        return key

    def save_tokens(self, access_token: str, refresh_token: str, expires_in: int):
        data = {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "expires_at": (datetime.now() + timedelta(seconds=expires_in)).isoformat()
        }
        encrypted_data = self.fernet.encrypt(json.dumps(data).encode())
        self.token_file.write_bytes(encrypted_data)
        self.token_file.chmod(0o600)

    def load_tokens(self) -> Optional[Dict[str, str]]:
        if not self.token_file.exists():
            return None
        try:
            encrypted_data = self.token_file.read_bytes()
            decrypted_data = self.fernet.decrypt(encrypted_data)
            return json.loads(decrypted_data.decode())
        except Exception as e:
            logger.error(f"Failed to load tokens: {e}")
            return None

    def is_token_expired(self, token_data: Dict[str, str]) -> bool:
        if not token_data or "expires_at" not in token_data:
            return True
        expires_at = datetime.fromisoformat(token_data["expires_at"])
        return datetime.now() >= expires_at - timedelta(minutes=5)  # Refresh 5 minutes early

class DiscordUserClient:
    def __init__(self):
        self.token_manager = TokenManager()
        self.access_token = None
        self.session = None

    async def ensure_authenticated(self):
        """Ensure we have a valid access token"""
        token_data = self.token_manager.load_tokens()

        if token_data and not self.token_manager.is_token_expired(token_data):
            self.access_token = token_data["access_token"]
            return

        if token_data and "refresh_token" in token_data:
            # Try to refresh the token
            if await self.refresh_token(token_data["refresh_token"]):
                return

        # Need to do full OAuth2 flow
        await self.perform_oauth2_flow()

    async def refresh_token(self, refresh_token: str) -> bool:
        """Refresh the access token using refresh token"""
        try:
            async with aiohttp.ClientSession() as session:
                data = {
                    "client_id": DISCORD_CLIENT_ID,
                    "client_secret": DISCORD_CLIENT_SECRET,
                    "grant_type": "refresh_token",
                    "refresh_token": refresh_token
                }

                async with session.post(
                    f"{DISCORD_API_BASE}/oauth2/token",
                    data=data
                ) as response:
                    if response.status == 200:
                        token_info = await response.json()
                        self.access_token = token_info["access_token"]
                        self.token_manager.save_tokens(
                            token_info["access_token"],
                            token_info.get("refresh_token", refresh_token),
                            token_info["expires_in"]
                        )
                        return True
                    else:
                        logger.error(f"Token refresh failed: {await response.text()}")
                        return False
        except Exception as e:
            logger.error(f"Token refresh error: {e}")
            return False

    async def perform_oauth2_flow(self):
        """Perform the OAuth2 authorization code flow"""
        # Generate PKCE challenge
        code_verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode('utf-8').rstrip('=')
        code_challenge = base64.urlsafe_b64encode(
            hashlib.sha256(code_verifier.encode()).digest()
        ).decode('utf-8').rstrip('=')

        # Generate state for security
        state = secrets.token_urlsafe(32)

        # Authorization URL
        auth_params = {
            "client_id": DISCORD_CLIENT_ID,
            "redirect_uri": DISCORD_REDIRECT_URI,
            "response_type": "code",
            "scope": " ".join(REQUIRED_SCOPES),
            "state": state,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256"
        }

        auth_url = f"https://discord.com/oauth2/authorize?{urlencode(auth_params)}"

        logger.info(f"Opening authorization URL: {auth_url}")
        webbrowser.open(auth_url)

        # Start local server to handle callback
        authorization_code = await self.start_callback_server(state)

        # Exchange code for tokens
        await self.exchange_code_for_tokens(authorization_code, code_verifier)

    async def start_callback_server(self, expected_state: str) -> str:
        """Start a local server to handle the OAuth2 callback"""
        authorization_code = None

        async def callback_handler(request):
            nonlocal authorization_code
            query = parse_qs(str(request.url).split('?')[1] if '?' in str(request.url) else '')

            if 'error' in query:
                error_msg = f"Authorization failed: {query.get('error_description', ['Unknown error'])[0]}"
                logger.error(error_msg)
                return web.Response(text=f"Authorization failed: {error_msg}", status=400)

            if 'state' not in query or query['state'][0] != expected_state:
                return web.Response(text="Invalid state parameter", status=400)

            if 'code' in query:
                authorization_code = query['code'][0]
                return web.Response(text="Authorization successful! You can close this window.")

            return web.Response(text="Missing authorization code", status=400)

        app_server = web.Application()
        app_server.router.add_get('/callback', callback_handler)

        runner = web.AppRunner(app_server)
        await runner.setup()

        # Extract port from redirect URI
        parsed_uri = urlparse(DISCORD_REDIRECT_URI)
        port = parsed_uri.port or 8000

        site = web.TCPSite(runner, 'localhost', port)
        await site.start()

        logger.info(f"Callback server started on port {port}")

        # Wait for authorization code
        while authorization_code is None:
            await asyncio.sleep(0.1)

        await runner.cleanup()
        return authorization_code

    async def exchange_code_for_tokens(self, authorization_code: str, code_verifier: str):
        """Exchange authorization code for access tokens"""
        async with aiohttp.ClientSession() as session:
            data = {
                "client_id": DISCORD_CLIENT_ID,
                "client_secret": DISCORD_CLIENT_SECRET,
                "grant_type": "authorization_code",
                "code": authorization_code,
                "redirect_uri": DISCORD_REDIRECT_URI,
                "code_verifier": code_verifier
            }

            async with session.post(
                f"{DISCORD_API_BASE}/oauth2/token",
                data=data
            ) as response:
                if response.status == 200:
                    token_info = await response.json()
                    self.access_token = token_info["access_token"]
                    self.token_manager.save_tokens(
                        token_info["access_token"],
                        token_info["refresh_token"],
                        token_info["expires_in"]
                    )
                    logger.info("OAuth2 flow completed successfully")
                else:
                    error_text = await response.text()
                    raise RuntimeError(f"Token exchange failed: {error_text}")

    async def make_request(self, method: str, endpoint: str, **kwargs) -> Dict:
        """Make an authenticated request to Discord API"""
        await self.ensure_authenticated()

        if not self.session:
            self.session = aiohttp.ClientSession()

        headers = kwargs.get('headers', {})
        headers['Authorization'] = f'Bearer {self.access_token}'
        headers['User-Agent'] = 'DiscordMCP/1.0'
        kwargs['headers'] = headers

        url = f"{DISCORD_API_BASE}{endpoint}"

        async with self.session.request(method, url, **kwargs) as response:
            if response.status == 401:
                # Token might be expired, try to refresh and retry once
                token_data = self.token_manager.load_tokens()
                if token_data and "refresh_token" in token_data:
                    if await self.refresh_token(token_data["refresh_token"]):
                        headers['Authorization'] = f'Bearer {self.access_token}'
                        async with self.session.request(method, url, **kwargs) as retry_response:
                            if retry_response.status >= 400:
                                raise RuntimeError(f"API request failed: {retry_response.status} - {await retry_response.text()}")
                            return await retry_response.json()
                raise RuntimeError("Authentication failed and token refresh unsuccessful")

            if response.status >= 400:
                raise RuntimeError(f"API request failed: {response.status} - {await response.text()}")

            return await response.json()

    async def get_user_guilds(self) -> List[Dict]:
        """Get guilds the user is a member of"""
        return await self.make_request('GET', '/users/@me/guilds')

    async def get_guild_channels(self, guild_id: str) -> List[Dict]:
        """Get channels in a guild"""
        return await self.make_request('GET', f'/guilds/{guild_id}/channels')

    async def get_channel_messages(self, channel_id: str, limit: int = 50, before: str = None) -> List[Dict]:
        """Get messages from a channel"""
        params = {'limit': min(limit, 100)}
        if before:
            params['before'] = before
        return await self.make_request('GET', f'/channels/{channel_id}/messages', params=params)

    async def get_guild_members(self, guild_id: str, limit: int = 1000) -> List[Dict]:
        """Get members of a guild"""
        params = {'limit': min(limit, 1000)}
        return await self.make_request('GET', f'/guilds/{guild_id}/members', params=params)

    async def get_user(self, user_id: str) -> Dict:
        """Get user information"""
        return await self.make_request('GET', f'/users/{user_id}')

    async def get_guild(self, guild_id: str) -> Dict:
        """Get guild information"""
        return await self.make_request('GET', f'/guilds/{guild_id}')

    async def close(self):
        """Close the HTTP session"""
        if self.session:
            await self.session.close()

# Initialize Discord client
discord_client = DiscordUserClient()

# Helper function to ensure Discord client is ready
def require_discord_client(func):
    @wraps(func)
    async def wrapper(*args, **kwargs):
        logger.info(f"🔒 Authentication check starting for {func.__name__}")
        try:
            await discord_client.ensure_authenticated()
            logger.info(f"🔓 Authentication successful for {func.__name__}")
            return await func(*args, **kwargs)
        except Exception as e:
            logger.error(f"❌ Authentication failed for {func.__name__}: {e}")
            raise
    return wrapper

@app.list_tools()
async def list_tools() -> List[Tool]:
    """List available Discord tools for user authentication."""
    logger.info("📋 list_tools() called - returning Discord tools")
    tools = [
        # Server Information Tools
        Tool(
            name="list_servers",
            description="Get a list of all Discord servers you have access to with their details such as name, id, member count, and creation date.",
            inputSchema={
                "type": "object",
                "properties": {},
                "required": []
            }
        ),
        Tool(
            name="get_server_info",
            description="Get information about a Discord server you have access to",
            inputSchema={
                "type": "object",
                "properties": {
                    "server_id": {
                        "type": "string",
                        "description": "Discord server (guild) ID"
                    }
                },
                "required": ["server_id"]
            }
        ),
        Tool(
            name="get_channels",
            description="Get a list of all channels in a Discord server you have access to",
            inputSchema={
                "type": "object",
                "properties": {
                    "server_id": {
                        "type": "string",
                        "description": "Discord server (guild) ID"
                    }
                },
                "required": ["server_id"]
            }
        ),
        Tool(
            name="list_members",
            description="Get a list of members in a server you have access to",
            inputSchema={
                "type": "object",
                "properties": {
                    "server_id": {
                        "type": "string",
                        "description": "Discord server (guild) ID"
                    },
                    "limit": {
                        "type": "number",
                        "description": "Maximum number of members to fetch",
                        "minimum": 1,
                        "maximum": 1000
                    }
                },
                "required": ["server_id"]
            }
        ),
        Tool(
            name="read_messages",
            description="Read recent messages from a channel you have access to",
            inputSchema={
                "type": "object",
                "properties": {
                    "channel_id": {
                        "type": "string",
                        "description": "Discord channel ID"
                    },
                    "limit": {
                        "type": "number",
                        "description": "Number of messages to fetch (max 100)",
                        "minimum": 1,
                        "maximum": 100
                    }
                },
                "required": ["channel_id"]
            }
        ),
        Tool(
            name="get_user_info",
            description="Get information about a Discord user",
            inputSchema={
                "type": "object",
                "properties": {
                    "user_id": {
                        "type": "string",
                        "description": "Discord user ID"
                    }
                },
                "required": ["user_id"]
            }
        ),
        Tool(
            name="test_connection",
            description="Test if the Discord MCP server is responding",
            inputSchema={
                "type": "object",
                "properties": {},
                "required": []
            }
        )
    ]
    logger.info(f"📋 Returning {len(tools)} Discord tools")
    return tools

@app.call_tool()
async def call_tool(name: str, arguments: Any) -> List[TextContent]:
    """Handle Discord tool calls using OAuth2 user authentication."""

    # Log immediately when tool is called, before any processing
    logger.info(f"📥 TOOL INVOCATION: {name} with args: {arguments}")
    start_time = datetime.now()

    # Skip authentication for test tool
    if name != "test_connection":
        # Manual authentication check with logging
        logger.info(f"🔒 Authentication check starting for {name}")
        try:
            await discord_client.ensure_authenticated()
            logger.info(f"🔓 Authentication successful for {name}")
        except Exception as e:
            logger.error(f"❌ Authentication failed for {name}: {e}")
            return [TextContent(type="text", text=f"Authentication error: {str(e)}")]

    logger.info(f"🔧 Processing tool: {name}")

    if name == "list_servers":
        try:
            guilds = await discord_client.get_user_guilds()
            servers = []
            for guild in guilds:
                # Calculate days since creation
                created_timestamp = int(guild['id']) >> 22
                created_date = datetime.fromtimestamp(created_timestamp / 1000 + 1420070400)  # Discord epoch

                servers.append({
                    "id": str(guild['id']),
                    "name": guild['name'],
                    "owner": guild.get('owner', False),
                    "permissions": guild.get('permissions', '0'),
                    "created_at": created_date.isoformat()
                })

            elapsed = (datetime.now() - start_time).total_seconds()
            logger.info(f"✅ list_servers completed in {elapsed:.2f}s")

            response = [TextContent(
                type="text",
                text=f"Available Servers ({len(servers)}):\n" +
                     "\n".join(f"{s['name']} (ID: {s['id']}, Owner: {s['owner']})" for s in servers)
            )]
            logger.info(f"📤 Sending response: {len(response[0].text)} characters")
            return response
        except Exception as e:
            elapsed = (datetime.now() - start_time).total_seconds()
            logger.error(f"❌ list_servers failed in {elapsed:.2f}s: {str(e)}")
            return [TextContent(type="text", text=f"Error fetching servers: {str(e)}")]

    elif name == "get_server_info":
        try:
            guild = await discord_client.get_guild(arguments["server_id"])

            # Calculate creation date from snowflake ID
            created_timestamp = int(guild['id']) >> 22
            created_date = datetime.fromtimestamp(created_timestamp / 1000 + 1420070400)  # Discord epoch

            info = {
                "name": guild['name'],
                "id": str(guild['id']),
                "icon": guild.get('icon'),
                "description": guild.get('description'),
                "splash": guild.get('splash'),
                "discovery_splash": guild.get('discovery_splash'),
                "owner_id": guild.get('owner_id'),
                "permissions": guild.get('permissions'),
                "region": guild.get('region'),
                "afk_channel_id": guild.get('afk_channel_id'),
                "afk_timeout": guild.get('afk_timeout'),
                "widget_enabled": guild.get('widget_enabled'),
                "widget_channel_id": guild.get('widget_channel_id'),
                "verification_level": guild.get('verification_level'),
                "default_message_notifications": guild.get('default_message_notifications'),
                "explicit_content_filter": guild.get('explicit_content_filter'),
                "mfa_level": guild.get('mfa_level'),
                "application_id": guild.get('application_id'),
                "system_channel_id": guild.get('system_channel_id'),
                "system_channel_flags": guild.get('system_channel_flags'),
                "rules_channel_id": guild.get('rules_channel_id'),
                "max_presences": guild.get('max_presences'),
                "max_members": guild.get('max_members'),
                "vanity_url_code": guild.get('vanity_url_code'),
                "banner": guild.get('banner'),
                "premium_tier": guild.get('premium_tier'),
                "premium_subscription_count": guild.get('premium_subscription_count'),
                "preferred_locale": guild.get('preferred_locale'),
                "public_updates_channel_id": guild.get('public_updates_channel_id'),
                "max_video_channel_users": guild.get('max_video_channel_users'),
                "approximate_member_count": guild.get('approximate_member_count'),
                "approximate_presence_count": guild.get('approximate_presence_count'),
                "nsfw_level": guild.get('nsfw_level'),
                "premium_progress_bar_enabled": guild.get('premium_progress_bar_enabled'),
                "created_at": created_date.isoformat()
            }

            # Filter out None values for cleaner output
            info = {k: v for k, v in info.items() if v is not None}

            return [TextContent(
                type="text",
                text=f"Server Information:\n" + "\n".join(f"{k}: {v}" for k, v in info.items())
            )]
        except Exception as e:
            return [TextContent(type="text", text=f"Error fetching server info: {str(e)}")]

    elif name == "get_channels":
        try:
            channels = await discord_client.get_guild_channels(arguments["server_id"])

            channel_types = {
                0: "Text",
                2: "Voice",
                4: "Category",
                5: "Announcement",
                10: "Announcement Thread",
                11: "Public Thread",
                12: "Private Thread",
                13: "Stage Voice",
                14: "Directory",
                15: "Forum"
            }

            channel_list = []
            for channel in channels:
                channel_type = channel_types.get(channel.get('type', 0), f"Unknown ({channel.get('type', 0)})")
                name = channel.get('name', 'Unnamed')
                if channel.get('type', 0) in [0, 5, 15]:  # Text channels
                    channel_list.append(f"#{name} (ID: {channel['id']}) - {channel_type}")
                else:
                    channel_list.append(f"{name} (ID: {channel['id']}) - {channel_type}")

            return [TextContent(
                type="text",
                text=f"Channels ({len(channels)}):\n" + "\n".join(channel_list)
            )]
        except Exception as e:
            return [TextContent(type="text", text=f"Error fetching channels: {str(e)}")]

    elif name == "list_members":
        try:
            limit = min(int(arguments.get("limit", 100)), 1000)
            members = await discord_client.get_guild_members(arguments["server_id"], limit)

            member_list = []
            for member in members:
                user = member.get('user', {})
                username = user.get('username', 'Unknown')
                discriminator = user.get('discriminator', '0000')
                display_name = f"{username}#{discriminator}" if discriminator != '0' else username
                nick = member.get('nick')
                if nick:
                    display_name += f" ({nick})"

                joined_at = member.get('joined_at')
                roles = member.get('roles', [])

                member_list.append({
                    "id": user.get('id'),
                    "display_name": display_name,
                    "joined_at": joined_at,
                    "roles": roles[1:] if len(roles) > 1 else []  # Skip @everyone
                })

            return [TextContent(
                type="text",
                text=f"Server Members ({len(member_list)}):\n" +
                     "\n".join(f"{m['display_name']} (ID: {m['id']}, Roles: {len(m['roles'])})" for m in member_list)
            )]
        except Exception as e:
            return [TextContent(type="text", text=f"Error fetching members: {str(e)}")]

    elif name == "read_messages":
        try:
            limit = min(int(arguments.get("limit", 10)), 100)
            messages = await discord_client.get_channel_messages(arguments["channel_id"], limit)

            formatted_messages = []
            for message in reversed(messages):  # Show oldest first
                author = message.get('author', {})
                username = author.get('username', 'Unknown')
                discriminator = author.get('discriminator', '0000')
                display_name = f"{username}#{discriminator}" if discriminator != '0' else username

                content = message.get('content', '')
                timestamp = message.get('timestamp', '')

                # Handle reactions
                reactions = message.get('reactions', [])
                reaction_text = ''
                if reactions:
                    reaction_list = []
                    for reaction in reactions:
                        emoji = reaction.get('emoji', {})
                        emoji_str = emoji.get('name', '❓')
                        count = reaction.get('count', 0)
                        reaction_list.append(f"{emoji_str}({count})")
                    reaction_text = f"\nReactions: {', '.join(reaction_list)}"

                # Handle embeds
                embeds = message.get('embeds', [])
                embed_text = ''
                if embeds:
                    embed_text = f"\n[Has {len(embeds)} embed(s)]"

                # Handle attachments
                attachments = message.get('attachments', [])
                attachment_text = ''
                if attachments:
                    attachment_names = [att.get('filename', 'unknown') for att in attachments]
                    attachment_text = f"\n[Attachments: {', '.join(attachment_names)}]"

                message_text = f"{display_name} ({timestamp}): {content}{reaction_text}{embed_text}{attachment_text}"
                formatted_messages.append(message_text)

            return [TextContent(
                type="text",
                text=f"Retrieved {len(messages)} messages:\n\n" + "\n\n".join(formatted_messages)
            )]
        except Exception as e:
            return [TextContent(type="text", text=f"Error reading messages: {str(e)}")]

    elif name == "get_user_info":
        try:
            user = await discord_client.get_user(arguments["user_id"])

            # Calculate creation date from snowflake ID
            created_timestamp = int(user['id']) >> 22
            created_date = datetime.fromtimestamp(created_timestamp / 1000 + 1420070400)  # Discord epoch

            user_info = {
                "id": str(user['id']),
                "username": user.get('username', 'Unknown'),
                "discriminator": user.get('discriminator', '0000'),
                "global_name": user.get('global_name'),
                "avatar": user.get('avatar'),
                "bot": user.get('bot', False),
                "system": user.get('system', False),
                "mfa_enabled": user.get('mfa_enabled'),
                "banner": user.get('banner'),
                "accent_color": user.get('accent_color'),
                "locale": user.get('locale'),
                "verified": user.get('verified'),
                "email": user.get('email'),
                "flags": user.get('flags'),
                "premium_type": user.get('premium_type'),
                "public_flags": user.get('public_flags'),
                "created_at": created_date.isoformat()
            }

            # Filter out None values
            user_info = {k: v for k, v in user_info.items() if v is not None}

            return [TextContent(
                type="text",
                text=f"User Information:\n" + "\n".join(f"{k}: {v}" for k, v in user_info.items())
            )]
        except Exception as e:
            return [TextContent(type="text", text=f"Error fetching user info: {str(e)}")]

    elif name == "test_connection":
        elapsed = (datetime.now() - start_time).total_seconds()
        logger.info(f"✅ test_connection completed in {elapsed:.2f}s")
        return [TextContent(
            type="text",
            text=f"✅ Discord MCP server is responding! Test completed in {elapsed:.2f} seconds."
        )]

    raise ValueError(f"Unknown tool: {name}")

async def main():
    """Main entry point for the MCP Discord OAuth2 server."""
    logger.info("🚀 Starting Discord MCP OAuth2 server")
    logger.info(f"📁 Working directory: {os.getcwd()}")
    logger.info(f"🔑 Client ID configured: {'Yes' if DISCORD_CLIENT_ID else 'No'}")
    logger.info(f"🔐 Client Secret configured: {'Yes' if DISCORD_CLIENT_SECRET else 'No'}")

    try:
        # Run MCP server
        logger.info("📡 MCP server starting stdio communication")
        async with stdio_server() as (read_stream, write_stream):
            logger.info("📡 MCP stdio streams established")
            await app.run(
                read_stream,
                write_stream,
                app.create_initialization_options()
            )
    except KeyboardInterrupt:
        logger.info("🛑 Received shutdown signal")
    except Exception as e:
        logger.error(f"💥 MCP server error: {e}", exc_info=True)
        raise
    finally:
        # Ensure proper cleanup
        logger.info("🔧 Cleaning up Discord client")
        try:
            await discord_client.close()
        except Exception as cleanup_error:
            logger.error(f"Cleanup error: {cleanup_error}")

if __name__ == "__main__":
    asyncio.run(main())
