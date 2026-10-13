# jwt-proxy

A lightweight, open-source reverse proxy that validates Cloudflare Access JWT tokens (RS256) against a JWKS endpoint and forwards authenticated requests to an upstream target.

## Features

- **JWT verification** — validates RS256 tokens from Cloudflare Access using the team's JWKS URL
- **JWKS caching** — caches the JWKS keys for 30 minutes (configurable) to avoid excessive fetches
- **Transparent proxying** — forwards all authenticated requests to `TARGET_HOST` with headers intact
- **403 on failure** — returns `403 Forbidden` with error details when JWT validation fails
- **Health check** — exposes `/healthz` (no auth required) for container orchestration
- **Non-root container** — runs as unprivileged user for security
- **Tiny image** — ~50MB on `node:24-alpine`

## Quick Start

```bash
docker run -d \
  --name jwt-proxy \
  -p 127.0.0.1:8080:8080 \
  -e TARGET_HOST=https://your-internal-app.example.com \
  -e CLOUDFLARE_JWKS_URL=https://your-team.cloudflareaccess.com/cdn-cgi/access/certs \
  -e CLOUDFLARE_AUD_TOKEN=your-aud-token-here \
  ghcr.io/timc1004/jwt-proxy:latest
```


## Docker Compose with Cloudflare Tunnel

This example uses a remotely managed Cloudflare Tunnel. Traffic flows through Cloudflare Access, `cloudflared`, this proxy, then your existing upstream application. Neither container publishes a host port.

1. Create a tunnel in Cloudflare and copy its connector token.
2. Add a published application route for your hostname (for example, `app.example.com`) with service URL `http://jwt-proxy:8080`.
3. Create a **self-hosted Cloudflare Access application** for that hostname and configure an Allow policy for your users. Copy its Application Audience (AUD) value. Creating a tunnel alone does not configure Access.
4. Save the following as `compose.yaml`:

```yaml
services:
  jwt-proxy:
    image: ghcr.io/timc1004/jwt-proxy:latest
    restart: unless-stopped
    environment:
      TARGET_HOST: ${TARGET_HOST:?Set TARGET_HOST}
      CLOUDFLARE_JWKS_URL: https://${CLOUDFLARE_TEAM:?Set CLOUDFLARE_TEAM}.cloudflareaccess.com/cdn-cgi/access/certs
      CLOUDFLARE_AUD_TOKEN: ${CLOUDFLARE_AUD_TOKEN:?Set CLOUDFLARE_AUD_TOKEN}
      DEBUG: "false"
    read_only: true
    cap_drop:
      - ALL
    security_opt:
      - no-new-privileges:true

  cloudflared:
    image: cloudflare/cloudflared:latest
    restart: unless-stopped
    command: tunnel --no-autoupdate run
    environment:
      TUNNEL_TOKEN: ${CLOUDFLARE_TUNNEL_TOKEN:?Set CLOUDFLARE_TUNNEL_TOKEN}
    depends_on:
      jwt-proxy:
        condition: service_healthy
    read_only: true
    cap_drop:
      - ALL
    security_opt:
      - no-new-privileges:true
```

5. Create a `.env` beside `compose.yaml`:

```dotenv
# Reachable from inside the proxy container; localhost is the container itself.
TARGET_HOST=http://192.168.1.20:3000
# Team subdomain only, without https:// or .cloudflareaccess.com.
CLOUDFLARE_TEAM=your-team
CLOUDFLARE_AUD_TOKEN=your-application-audience
CLOUDFLARE_TUNNEL_TOKEN=your-tunnel-connector-token
```

Protect `.env` (`chmod 600 .env` on Linux), keep it out of version control, then run:

```bash
docker compose config --quiet
docker compose up -d
docker compose logs --tail=50 jwt-proxy cloudflared
```

Open your hostname and sign in through Access. The proxy validates the `cf-access-jwt-assertion` header supplied by Access. The tunnel token authenticates the connector; it is not the application's AUD value or a user's JWT. Treat the tunnel token as a secret.

If your upstream is another Compose service, attach the proxy to its Docker network and use its service name, such as `http://app:3000`. Restrict direct access to the upstream with network/firewall rules so clients cannot bypass this proxy. Use HTTPS for upstream traffic crossing an untrusted network.

For production, pin both images to a tested release tag or digest. The build workflow publishes images on `v*` tags; updating documentation does not rebuild an image.

See [Cloudflare Tunnel setup](https://developers.cloudflare.com/tunnel/get-started/) and [tunnel run parameters](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/configure-tunnels/run-parameters/).

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `TARGET_HOST` | `http://localhost:3000` | Upstream URL to forward authenticated requests to |
| `CLOUDFLARE_JWKS_URL` | *(required)* | Cloudflare Access JWKS endpoint (e.g. `https://<team>.cloudflareaccess.com/cdn-cgi/access/certs`) |
| `CLOUDFLARE_AUD_TOKEN` | *(required)* | Expected `aud` claim value (your Cloudflare Application Audience) |
| `CLOUDFLARE_ISSUER` | *(derived from JWKS URL)* | Expected `iss` claim (e.g. `https://your-team.cloudflareaccess.com`) |
| `JWKS_CACHE_TTL_MS` | `1800000` | JWKS cache TTL in milliseconds |
| `ALLOWED_USERS` | *(not set)* | Optional comma-separated email/domain allowlist, e.g. `user@example.com,@company.com`; otherwise any valid token for this application is accepted |
| `JWKS_FETCH_TIMEOUT_MS` | `5000` | Timeout for fetching JWKS headers and response body |
| `JWKS_REFRESH_COOLDOWN_MS` | `30000` | Minimum interval between completed refresh attempts, including failures |
| `BYPASS_PATHS` | *(not set)* | JSON array of JavaScript regex strings for paths that skip JWT verification (e.g. `["^/public/","^/webhook$"]`) |
| `PORT` | `8080` | Port the proxy listens on |
| `DEBUG` | `false` | Enable verbose request/JWT debug logging |

## Usage

Once running, point your Cloudflare Application's domain at this proxy. All requests will:

1. Have their `cf-access-jwt-assertion` header (or `Authorization: Bearer <token>` fallback) validated for RS256 signature, audience and issuer
2. Be forwarded to `TARGET_HOST` if valid (with original headers, query params, body)
3. Receive a `403 Forbidden` response if validation fails

```bash
# Test with a token
curl -H "Authorization: Bearer <your-jwt>" http://localhost:8080/api/data

# Health check
curl http://localhost:8080/healthz
```

## Architecture

```
Client (Cloudflare Access)
    │
    ▼
┌─────────────────┐
│   jwt-proxy     │
│  :8080          │
│                 │
│  1. Extract JWT│
│  2. Fetch JWKS │◄── cache 30min
│  3. Verify RS256│
│  4. Proxy or 403│
└────────┬────────┘
         │
         ▼
   TARGET_HOST
```

## Security considerations

- Leave `BYPASS_PATHS` unset unless an endpoint is intentionally public. Expressions match the raw request path; use anchors and check URL encoding, dot segments, and upstream path normalization before allowing bypasses.
- The proxy forwards original request headers. Upstream applications must not trust client-supplied identity headers such as `Cf-Access-Authenticated-User-Email` or `X-Forwarded-User` as proof of identity; this proxy does not replace them with verified JWT claims.
- JWT expiry is checked when `exp` exists, but the current verifier does not require that claim. It also does not explicitly require Cloudflare's application token type.
- Unknown JWT key IDs can request a JWKS refresh, but all callers share a single in-flight fetch. Fetches time out after five seconds and refresh attempts are throttled for 30 seconds after completion, including failures. Valid cached keys remain usable until their TTL expires; expired keys fail closed if a refresh is unavailable. A newly rotated key may be rejected until the cooldown ends. Keep Access policies enforced at the edge and restrict direct origin access.
- Keep `DEBUG` disabled in production unless diagnosing an issue; logs can include user identities and request paths.

## Building Locally

```bash
docker build -t jwt-proxy .
```

## Regression checks

```bash
node --test jwks-cache.test.js
```

## License

MIT
