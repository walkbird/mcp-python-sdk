import logging
import secrets
import time
from typing import Literal

import click
from pydantic import AnyHttpUrl
from pydantic_settings import BaseSettings, SettingsConfigDict

from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.server.auth.provider import (
    AccessToken,
    AuthorizationCode,
    AuthorizationParams,
    OAuthAuthorizationServerProvider,
    RefreshToken,
    construct_redirect_uri,
    TokenError,
)
from mcp.server.auth.settings import (
    AuthSettings,
    ClientRegistrationOptions,
    RevocationOptions,
)
from mcp.server.fastmcp.server import FastMCP
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken

logger = logging.getLogger(__name__)


class ServerSettings(BaseSettings):
    """Settings for the in-memory OAuth demo server."""

    model_config = SettingsConfigDict(env_prefix="MCP_MEMAUTH_")

    host: str = "localhost"
    port: int = 8000
    server_url: AnyHttpUrl = AnyHttpUrl("http://localhost:8000")


class InMemoryOAuthProvider(OAuthAuthorizationServerProvider):
    """Simple in-memory OAuth provider for demo purposes."""

    def __init__(self):
        self.clients: dict[str, OAuthClientInformationFull] = {}
        self.auth_codes: dict[str, AuthorizationCode] = {}
        self.access_tokens: dict[str, AccessToken] = {}
        self.refresh_tokens: dict[str, RefreshToken] = {}

    async def get_client(self, client_id: str) -> OAuthClientInformationFull | None:
        return self.clients.get(client_id)

    async def register_client(self, client_info: OAuthClientInformationFull) -> None:
        self.clients[client_info.client_id] = client_info

    async def authorize(
        self, client: OAuthClientInformationFull, params: AuthorizationParams
    ) -> str:
        code_value = secrets.token_hex(16)
        code = AuthorizationCode(
            code=code_value,
            client_id=client.client_id,
            code_challenge=params.code_challenge,
            redirect_uri=params.redirect_uri,
            redirect_uri_provided_explicitly=params.redirect_uri_provided_explicitly,
            expires_at=time.time() + 300,
            scopes=params.scopes or [],
        )
        self.auth_codes[code_value] = code
        return construct_redirect_uri(str(params.redirect_uri), code=code_value, state=params.state)

    async def load_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: str
    ) -> AuthorizationCode | None:
        return self.auth_codes.get(authorization_code)

    async def exchange_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: AuthorizationCode
    ) -> OAuthToken:
        if authorization_code.code not in self.auth_codes:
            raise TokenError("invalid_grant", "authorization code does not exist")

        access_token_value = secrets.token_hex(32)
        refresh_token_value = secrets.token_hex(32)

        access = AccessToken(
            token=access_token_value,
            client_id=client.client_id,
            scopes=authorization_code.scopes,
            expires_at=int(time.time()) + 3600,
        )
        refresh = RefreshToken(
            token=refresh_token_value,
            client_id=client.client_id,
            scopes=authorization_code.scopes,
            expires_at=None,
        )

        self.access_tokens[access_token_value] = access
        self.refresh_tokens[refresh_token_value] = refresh
        del self.auth_codes[authorization_code.code]

        return OAuthToken(
            access_token=access_token_value,
            token_type="bearer",
            expires_in=3600,
            refresh_token=refresh_token_value,
            scope=" ".join(authorization_code.scopes),
        )

    async def load_refresh_token(
        self, client: OAuthClientInformationFull, refresh_token: str
    ) -> RefreshToken | None:
        token = self.refresh_tokens.get(refresh_token)
        if token and token.client_id == client.client_id:
            return token
        return None

    async def exchange_refresh_token(
        self,
        client: OAuthClientInformationFull,
        refresh_token: RefreshToken,
        scopes: list[str],
    ) -> OAuthToken:
        if refresh_token.token not in self.refresh_tokens:
            raise TokenError("invalid_grant", "refresh token does not exist")

        new_access_value = secrets.token_hex(32)
        new_refresh_value = secrets.token_hex(32)

        access = AccessToken(
            token=new_access_value,
            client_id=client.client_id,
            scopes=scopes or refresh_token.scopes,
            expires_at=int(time.time()) + 3600,
        )
        new_refresh = RefreshToken(
            token=new_refresh_value,
            client_id=client.client_id,
            scopes=scopes or refresh_token.scopes,
            expires_at=None,
        )

        self.access_tokens[new_access_value] = access
        self.refresh_tokens[new_refresh_value] = new_refresh
        del self.refresh_tokens[refresh_token.token]

        return OAuthToken(
            access_token=new_access_value,
            token_type="bearer",
            expires_in=3600,
            refresh_token=new_refresh_value,
            scope=" ".join(scopes) if scopes else " ".join(refresh_token.scopes),
        )

    async def load_access_token(self, token: str) -> AccessToken | None:
        return self.access_tokens.get(token)

    async def revoke_token(self, token: AccessToken | RefreshToken) -> None:
        match token:
            case AccessToken():
                self.access_tokens.pop(token.token, None)
                # remove refresh tokens associated with this access token
                for rt, _token in list(self.refresh_tokens.items()):
                    if _token.token == token.token:
                        self.refresh_tokens.pop(rt, None)
            case RefreshToken():
                self.refresh_tokens.pop(token.token, None)


def create_demo_server(settings: ServerSettings) -> FastMCP:
    provider = InMemoryOAuthProvider()
    auth_settings = AuthSettings(
        issuer_url=settings.server_url,
        client_registration_options=ClientRegistrationOptions(
            enabled=True,
            valid_scopes=["basic"],
            default_scopes=["basic"],
        ),
        revocation_options=RevocationOptions(enabled=True),
        required_scopes=["basic"],
    )

    app = FastMCP(
        name="Simple Memory OAuth Server",
        instructions="A minimal server demonstrating OAuth support",
        auth_server_provider=provider,
        host=settings.host,
        port=settings.port,
        debug=True,
        auth=auth_settings,
    )

    @app.tool()
    async def hello() -> str:
        """Return a friendly greeting."""
        token = get_access_token()
        if not token:
            raise ValueError("Not authenticated")
        return f"Hello from {token.client_id}!"

    return app


@click.command()
@click.option("--port", default=8000, help="Port to listen on")
@click.option("--host", default="localhost", help="Host to bind to")
@click.option(
    "--transport",
    default="sse",
    type=click.Choice(["sse", "streamable-http"]),
    help="Transport protocol to use ('sse' or 'streamable-http')",
)
def main(port: int, host: str, transport: Literal["sse", "streamable-http"]) -> int:
    """Run the memory OAuth MCP server."""
    logging.basicConfig(level=logging.INFO)
    settings = ServerSettings(host=host, port=port, server_url=f"http://{host}:{port}")
    mcp_server = create_demo_server(settings)
    logger.info(f"Starting server with {transport} transport")
    mcp_server.run(transport=transport)
    return 0

