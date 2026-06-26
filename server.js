const express = require('express');
const jwt = require('jsonwebtoken');
const { createPublicKey } = require('crypto');
const fetch = require('node-fetch');
const { createProxyServer } = require('http-proxy');

const app = express();
const proxy = createProxyServer();

// ─── Configuration ───────────────────────────────────────────────
const TARGET_HOST = process.env.TARGET_HOST || 'http://localhost:3000';
const CLOUDFLARE_JWKS_URL = process.env.CLOUDFLARE_JWKS_URL;
const CLOUDFLARE_AUD_TOKEN = process.env.CLOUDFLARE_AUD_TOKEN;
const PORT = process.env.PORT || 8080;
const JWKS_CACHE_TTL_MS = 30 * 60 * 1000; // 30 minutes
const DEBUG = process.env.DEBUG === 'true' || process.env.DEBUG === '1';

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
  debug('JWT header', { kid: decodedHeader.header.kid, alg: decodedHeader.header.alg });

  return fetchKey(decodedHeader.header).then(publicKey => {
    return new Promise((resolve, reject) => {
      jwt.verify(
        token,
        publicKey,
        {
          algorithms: ['RS256'],
          audience: CLOUDFLARE_AUD_TOKEN,
        },
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
  debug('Incoming request', { method: req.method, path: req.path, ip: req.ip, headers: Object.keys(req.headers) });

  // Health check endpoint (no auth required)
  if (req.path === '/healthz') {
    return res.status(200).json({ status: 'ok' });
  }

  const token = extractBearerToken(req);
  if (!token) {
    debug('No bearer token found', { authorization: req.headers['authorization'] || '(absent)' });
    return res.status(403).json({
      error: 'Forbidden',
      message: 'Missing or malformed Authorization header'
    });
  }

  debug('Token received', { token_preview: token.substring(0, 20) + '...' });

  try {
    const decoded = await verifyToken(token);
    req.jwtPayload = decoded;
    debug('JWT verified successfully', { sub: decoded.sub, aud: decoded.aud, exp: decoded.exp });
    next();
  } catch (err) {
    log('WARN', 'JWT verification failed', { error: err.message });
    return res.status(403).json({
      error: 'Forbidden',
      message: err.message
    });
  }
});

// Proxy everything else to target
app.use((req, res) => {
  debug('Proxying to target', { target: TARGET_HOST, path: req.path });
  proxy.web(req, res, { target: TARGET_HOST, changeOrigin: true }, (err) => {
    if (err) {
      log('ERROR', 'Proxy error', { error: err.message });
      res.status(502).json({ error: 'Bad Gateway', message: err.message });
    }
  });
});

// ─── Start ───────────────────────────────────────────────────────
app.listen(PORT, '0.0.0.0', () => {
  log('INFO', `jwt-proxy listening on port ${PORT}`);
  log('INFO', `  TARGET_HOST: ${TARGET_HOST}`);
  log('INFO', `  CLOUDFLARE_JWKS_URL: ${CLOUDFLARE_JWKS_URL || '(not set)'}`);
  log('INFO', `  CLOUDFLARE_AUD_TOKEN: ${CLOUDFLARE_AUD_TOKEN ? '***' + CLOUDFLARE_AUD_TOKEN.slice(-6) : '(not set)'}`);
  log('INFO', `  JWKS cache TTL: ${JWKS_CACHE_TTL_MS / 60000} minutes`);
  log('INFO', `  DEBUG mode: ${DEBUG ? 'on' : 'off'}`);
});
