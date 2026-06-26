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
  -p 8080:8080 \
  -e TARGET_HOST=https://your-internal-app.example.com \
  -e CLOUDFLARE_JWKS_URL=https://your-team.cloudflareaccess.com/cdn-cgi/access/certs \
  -e CLOUDFLARE_AUD_TOKEN=your-aud-token-here \
  ghcr.io/YOUR_USER/jwt-proxy:latest
```

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `TARGET_HOST` | `http://localhost:3000` | Upstream URL to forward authenticated requests to |
| `CLOUDFLARE_JWKS_URL` | *(required)* | Cloudflare Access JWKS endpoint (e.g. `https://<team>.cloudflareaccess.com/cdn-cgi/access/certs`) |
| `CLOUDFLARE_AUD_TOKEN` | *(required)* | Expected `aud` claim value (your Cloudflare Application Audience) |
| `CLOUDFLARE_ISSUER` | *(derived from JWKS URL)* | Expected `iss` claim (e.g. `https://your-team.cloudflareaccess.com`) |
| `PORT` | `8080` | Port the proxy listens on |
| `DEBUG` | `false` | Enable verbose request/JWT debug logging |

## Usage

Once running, point your Cloudflare Application's domain at this proxy. All requests will:

1. Have their `Authorization: Bearer <token>` header validated against the JWKS keys
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

## Building Locally

```bash
docker build -t jwt-proxy .
```

## License

MIT
