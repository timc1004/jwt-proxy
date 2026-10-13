// A single refresh is shared by all callers, including unknown-kid requests.
function createJwksCache({ url, ttlMs, timeoutMs, cooldownMs, validate,
  fetchFn = fetch, now = Date.now }) {
  let cached = null;
  let cachedAt = 0;
  let nextRefreshAt = 0;
  let inFlight = null;

  return async function getJwks({ forceRefresh = false } = {}) {
    if (!forceRefresh && cached && now() - cachedAt < ttlMs) return cached;
    if (inFlight) return inFlight;
    if (now() < nextRefreshAt) {
      if (cached && now() - cachedAt < ttlMs) return cached;
      throw new Error('JWKS refresh temporarily unavailable');
    }

    // Set before fetching so failures are throttled too.
    nextRefreshAt = now() + cooldownMs;
    inFlight = (async () => {
      const response = await fetchFn(url, {
        signal: AbortSignal.timeout(timeoutMs),
        redirect: 'error',
      });
      if (!response.ok) throw new Error(`Failed to fetch JWKS: ${response.status}`);
      const jwks = await response.json();
      validate(jwks);
      cached = jwks;
      cachedAt = now();
      return cached;
    })();
    try {
      return await inFlight;
    } finally {
      inFlight = null;
      nextRefreshAt = now() + cooldownMs;
    }
  };
}

module.exports = { createJwksCache };
