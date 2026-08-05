# NOWADAYS ApparelMagic MCP OAuth Proxy

This service connects ChatGPT to the ApparelMagic MCP endpoint without exposing the ApparelMagic API key to the client. It provides an OAuth 2.0 authorization-code flow with PKCE, validates short-lived bearer tokens, and forwards authenticated MCP requests to ApparelMagic with the configured `X-API-Key` header.

## How it works

1. ChatGPT discovers the OAuth and protected-resource metadata.
2. The MCP client dynamically registers its redirect URI.
3. An administrator authorizes access with the configured password.
4. The client exchanges the one-time authorization code and PKCE verifier for an access token.
5. Requests to `/mcp` are authenticated and proxied to ApparelMagic.

The ApparelMagic API key remains server-side throughout this flow.

## Requirements

- Node.js 20 or newer
- A public HTTPS URL for the deployed service
- An ApparelMagic API key

## Installation

Install the exact dependency versions recorded in `package-lock.json`:

```bash
npm ci
```

## Configuration

Set these environment variables in the deployment platform. Never commit their values.

| Variable | Required | Description |
| --- | --- | --- |
| `PUBLIC_BASE_URL` | Yes* | Public HTTPS origin of this service, without a trailing slash |
| `RENDER_EXTERNAL_URL` | Yes* | Render-provided fallback when `PUBLIC_BASE_URL` is not set |
| `APPARELMAGIC_API_KEY` | Yes | Secret API key added to upstream requests as `X-API-Key` |
| `OAUTH_ADMIN_PASSWORD` | Yes | Password used on the authorization screen |
| `JWT_SECRET` | Yes | High-entropy secret used to sign clients, codes, and tokens |
| `PORT` | No | HTTP port; defaults to `3000` |
| `UPSTREAM_MCP_URL` | No | ApparelMagic MCP endpoint; defaults to `https://api.apparelmagic.com/mcp` |
| `OAUTH_SCOPE` | No | Granted OAuth scope; defaults to `mcp:tools:read` |

\* Set either `PUBLIC_BASE_URL` or `RENDER_EXTERNAL_URL`.

Generate strong secrets locally, for example:

```bash
openssl rand -base64 48
```

## Run locally

OAuth redirect URIs may use HTTP only for `localhost`; production deployments must use HTTPS.

```bash
export PUBLIC_BASE_URL=http://localhost:3000
export APPARELMAGIC_API_KEY=replace-me
export OAUTH_ADMIN_PASSWORD=replace-me
export JWT_SECRET=replace-with-a-long-random-secret
npm start
```

Verify the service:

```bash
curl http://localhost:3000/health
```

Expected response:

```json
{"ok":true,"service":"nowadays-apparelmagic-mcp"}
```

## Connect an MCP client

After deployment, configure the MCP server URL as:

```text
https://your-service.example/mcp
```

The client can discover OAuth configuration through:

- `/.well-known/oauth-authorization-server`
- `/.well-known/openid-configuration`
- `/.well-known/oauth-protected-resource`
- `/.well-known/oauth-protected-resource/mcp`

On first connection, complete the authorization page using `OAUTH_ADMIN_PASSWORD`.

## Endpoints

| Endpoint | Purpose |
| --- | --- |
| `GET /health` | Health check |
| `GET /` | Basic service status |
| `GET/POST /authorize` | Authorization and administrator approval |
| `POST /register` | Dynamic OAuth client registration |
| `POST /token` | Code exchange and refresh-token rotation |
| `ALL /mcp` | Authenticated ApparelMagic MCP proxy |

## Security notes

- Store all secrets only in the deployment platform's secret manager.
- Use a unique, high-entropy `JWT_SECRET` and rotate it if exposure is suspected.
- Keep `OAUTH_ADMIN_PASSWORD` separate from the ApparelMagic API key.
- Use HTTPS in production and restrict access to trusted users.
- The default scope is read-oriented, but actual capabilities also depend on the upstream ApparelMagic account and API key.
- Authorization-code replay protection is held in memory. Restarting the service clears that short-lived state, and horizontal scaling would require a shared store.

## Development and CI

Run the same checks used by GitHub Actions:

```bash
npm ci
npm run check
```

The CI workflow runs on pushes to `main` and on pull requests using Node.js 20. Dependabot alerts and normal dependency updates should keep `package-lock.json` synchronized with `package.json`.

## License

Private NOWADAYS integration. No license is granted for redistribution unless one is added explicitly.
