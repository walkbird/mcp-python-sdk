# Simple Memory OAuth Server

This example demonstrates how to use the authentication components in
`mcp.server.auth` to protect a tool using a minimal OAuth 2.0 server. All
clients, codes and tokens are stored in memory, so this server is intended only
for testing or learning purposes.

## Running

Use `uv` to run the server. By default it listens on `http://localhost:8000` and
provides the SSE transport on `/sse`.

```bash
uv run mcp-simple-memory-auth
```

To use the Streamable HTTP transport instead, pass `--transport streamable-http`:

```bash
uv run mcp-simple-memory-auth --transport streamable-http
```

## Endpoints

The server exposes the standard OAuth endpoints:

- `/.well-known/oauth-authorization-server` – metadata
- `/authorize` – request an authorization code (requires PKCE)
- `/token` – exchange an authorization code or refresh token
- `/register` – dynamic client registration
- `/revoke` – token revocation

It also exposes a single tool named `hello` that returns a greeting. Calling the
tool requires an OAuth access token with the `basic` scope.
