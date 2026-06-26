const express = require('express');
const jwt = require('jsonwebtoken');
const { createPublicKey } = require('crypto');
const { createProxyServer } = require('http-proxy');

const app = express();
const proxy = createProxyServer({
  proxyTimeout: 30_000,
  timeout: 30_000,
});

// ─── Configuration ───────────────────────────────────────────────
const TARGET_HOST = process.env.TARGET_HOST || 'http://localhost:3000';
const CLOUDFLARE_JWKS_URL = process.env.CLOUDFLARE_JWKS_URL;
const CLOUDFLARE_AUD_TOKEN = process.env.CLOUDFLARE_AUD_TOKEN;
const CLOUDFLARE_ISSUER = process.env.CLOUDFLARE_ISSUER;
const ALLOWED_USERS = process.env.ALLOWED_USERS;
const PORT = process.env.PORT || 8080;
const JWKS_CACHE_TTL_MS = 30 * 60 * 1000; // 30 minutes
const DEBUG = process.env.DEBUG === 'true' || process.env.DEBUG === '1';

function deriveIssuerFromJwksUrl(jwksUrl) {
  const url = new URL(jwksUrl);
  if (url.protocol !== 'https:') {
    throw new Error('CLOUDFLARE_JWKS_URL must use HTTPS');
  }
  return `${url.protocol}//${url.host}`;
}

function resolveIssuer() {
  if (CLOUDFLARE_ISSUER) {
    const issuer = new URL(CLOUDFLARE_ISSUER);
    if (issuer.protocol !== 'https:') {
      throw new Error('CLOUDFLARE_ISSUER must use HTTPS');
    }
    return issuer.origin;
  }
  if (!CLOUDFLARE_JWKS_URL) {
    return null;
  }
  return deriveIssuerFromJwksUrl(CLOUDFLARE_JWKS_URL);
}

const EXPECTED_ISSUER = resolveIssuer();

// ─── Allowed Users ────────────────────────────────────────────────
// Parse comma-separated list of email addresses or domains (e.g. "user@example.com,@company.com")
function parseAllowedUsers(raw) {
  if (!raw) return null; // no restriction
  return raw
    .split(',')
    .map(e => e.trim().toLowerCase())
    .filter(e => e.length > 0);
}

const ALLOWED_USERS_LIST = parseAllowedUsers(ALLOWED_USERS);

function isUserAllowed(email) {
  if (!ALLOWED_USERS_LIST) return true; // no restriction
  if (!email) return false;

  const normalizedEmail = email.toLowerCase();

  for (const entry of ALLOWED_USERS_LIST) {
    if (entry.startsWith('@')) {
      // Domain match: @company.com matches user@company.com
      const domain = entry.substring(1);
      if (normalizedEmail.endsWith(`@${domain}`)) {
        return true;
      }
    } else {
      // Exact email match
      if (normalizedEmail === entry) {
        return true;
      }
    }
  }
  return false;
}

// ─── Logging ─────────────────────────────────────────────────────
function log(level, msg, data) {
  const ts = new Date().toISOString();
  const line = data ? `${ts} [${level}] ${msg} ${JSON.stringify(data)}` : `${ts} [${level}] ${msg}`;
  console.log(line);
}

function debug(msg, data) {
  if (DEBUG) log('DEBUG', msg, data);
}

// ─── JWKS Cache ──────────────────────────────────────────────────
let jwksCache = null;
let jwksCacheTime = 0;

async function getJwks() {
  const now = Date.now();
  if (jwksCache && (now - jwksCacheTime) < JWKS_CACHE_TTL_MS) {
    debug('JWKS cache hit', { keys: jwksCache.keys?.length, cached_ms_ago: now - jwksCacheTime });
    return jwksCache;
  }

  if (!CLOUDFLARE_JWKS_URL) {
    throw new Error('CLOUDFLARE_JWKS_URL is not configured');
  }

  deriveIssuerFromJwksUrl(CLOUDFLARE_JWKS_URL);

  log('INFO', 'Fetching JWKS', { url: CLOUDFLARE_JWKS_URL });

  const res = await fetch(CLOUDFLARE_JWKS_URL);
  if (!res.ok) {
    throw new Error(`Failed to fetch JWKS: ${res.status} ${res.statusText}`);
  }
  const jwks = await res.json();
  jwksCache = jwks;
  jwksCacheTime = now;
  log('INFO', 'JWKS fetched and cached', { keys: jwks.keys?.length, ttl_min: JWKS_CACHE_TTL_MS / 60000 });
  return jwks;
}

// ─── JWT Verification ────────────────────────────────────────────
function fetchKey(header) {
  return getJwks().then(jwks => {
    debug('Looking up key', { kid: header.kid, available_kids: jwks.keys.map(k => k.kid) });
    const key = jwks.keys.find(k => k.kid === header.kid);
    if (!key) {
      throw new Error(`No matching key found for kid: ${header.kid}`);
    }
    const keyObject = createPublicKey({ key, format: 'jwk' });
    return keyObject.export({ format: 'pem', type: 'spki' });
  });
}

function verifyToken(token) {
  const decodedHeader = jwt.decode(token, { complete: true });
  if (!decodedHeader) {
    throw new Error('Could not decode JWT header');
  }

  if (decodedHeader.header.alg !== 'RS256') {
    throw new Error(`Unsupported JWT algorithm: ${decodedHeader.header.alg}`);
  }

  debug('JWT header', { kid: decodedHeader.header.kid, alg: decodedHeader.header.alg });

  return fetchKey(decodedHeader.header).then(publicKey => {
    return new Promise((resolve, reject) => {
      const verifyOptions = {
        algorithms: ['RS256'],
        audience: CLOUDFLARE_AUD_TOKEN,
      };
      if (EXPECTED_ISSUER) {
        verifyOptions.issuer = EXPECTED_ISSUER;
      }

      jwt.verify(
        token,
        publicKey,
        verifyOptions,
        (err, decoded) => {
          if (err) return reject(err);
          resolve(decoded);
        }
      );
    });
  });
}

// ─── Extract JWT Token ───────────────────────────────────────────
// Cloudflare Access sends the JWT in "cf-access-jwt-assertion",
// but we also support "Authorization: Bearer <token>" for direct use.
function extractBearerToken(req) {
  // 1. Check Cloudflare Access header
  const cfToken = req.headers['cf-access-jwt-assertion'];
  if (cfToken) {
    debug('Found token in cf-access-jwt-assertion header');
    return cfToken;
  }

  // 2. Check standard Authorization: Bearer <token>
  const authHeader = req.headers['authorization'];
  if (authHeader) {
    const parts = authHeader.split(' ');
    if (parts.length === 2 && parts[0] === 'Bearer') {
      debug('Found token in Authorization header');
      return parts[1];
    }
  }

  return null;
}

// ─── Routes ──────────────────────────────────────────────────────
app.use(async (req, res, next) => {
  debug('Incoming request', { method: req.method, path: req.path, ip: req.ip });

  // Health check endpoint (no auth required)
  if (req.path === '/healthz') {
    return res.status(200).json({ status: 'ok' });
  }

  const token = extractBearerToken(req);
  if (!token) {
    debug('No bearer token found');
    return res.status(403).json({
      error: 'Forbidden',
      message: 'Missing or malformed Authorization header',
    });
  }

  try {
    const decoded = await verifyToken(token);
    req.jwtPayload = decoded;
    debug('JWT verified successfully', { sub: decoded.sub, aud: decoded.aud, exp: decoded.exp });

    // Extract user email from JWT claims
    // Cloudflare Access uses "email", "identity_nonce", or custom claims
    const userEmail = decoded.email || decoded.sub || null;

    if (!isUserAllowed(userEmail)) {
      log('WARN', 'User not in allowed list', { email: userEmail });
      return res.status(403).json({
        error: 'Forbidden',
        message: 'User not authorized',
      });
    }

    debug('User authorized', { email: userEmail });
    next();
  } catch (err) {
    log('WARN', 'JWT verification failed', { error: err.message });
    return res.status(403).json({
      error: 'Forbidden',
      message: 'Invalid or expired token',
    });
  }
});

// Proxy everything else to target
app.use((req, res) => {
  debug('Proxying to target', { target: TARGET_HOST, path: req.path });
  proxy.web(req, res, { target: TARGET_HOST, changeOrigin: true }, (err) => {
    if (err) {
      log('ERROR', 'Proxy error', { error: err.message });
      if (!res.headersSent) {
        res.status(502).json({ error: 'Bad Gateway', message: 'Upstream request failed' });
      }
    }
  });
});

// ─── Start ───────────────────────────────────────────────────────
function validateConfig() {
  const missing = [];
  if (!CLOUDFLARE_JWKS_URL) missing.push('CLOUDFLARE_JWKS_URL');
  if (!CLOUDFLARE_AUD_TOKEN) missing.push('CLOUDFLARE_AUD_TOKEN');
  if (missing.length > 0) {
    throw new Error(`Missing required environment variables: ${missing.join(', ')}`);
  }

  try {
    deriveIssuerFromJwksUrl(CLOUDFLARE_JWKS_URL);
  } catch (err) {
    throw new Error(`Invalid CLOUDFLARE_JWKS_URL: ${err.message}`);
  }
}

validateConfig();

app.listen(PORT, '0.0.0.0', () => {
  log('INFO', `jwt-proxy listening on port ${PORT}`);
  log('INFO', `  TARGET_HOST: ${TARGET_HOST}`);
  log('INFO', `  CLOUDFLARE_JWKS_URL: ${CLOUDFLARE_JWKS_URL}`);
  log('INFO', `  CLOUDFLARE_AUD_TOKEN: ***${CLOUDFLARE_AUD_TOKEN.slice(-6)}`);
  log('INFO', `  CLOUDFLARE_ISSUER: ${EXPECTED_ISSUER || '(derived from JWKS URL)'}`);
  log('INFO', `  ALLOWED_USERS: ${ALLOWED_USERS_LIST ? ALLOWED_USERS_LIST.join(', ') : '(not set, all users allowed)'}`);
  log('INFO', `  JWKS cache TTL: ${JWKS_CACHE_TTL_MS / 60000} minutes`);
  log('INFO', `  DEBUG mode: ${DEBUG ? 'on' : 'off'}`);
});
