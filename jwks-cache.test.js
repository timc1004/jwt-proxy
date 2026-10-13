const { test } = require('node:test');
const assert = require('node:assert/strict');
const { createJwksCache } = require('./jwks-cache');

function fixture(fetchFn) {
  let time = 1000;
  const get = createJwksCache({ url: 'https://example.test/certs', ttlMs: 1000,
    cooldownMs: 100, timeoutMs: 20, fetchFn, now: () => time,
    validate: value => assert.ok(value.keys.length) });
  return { get, advance: ms => { time += ms; } };
}
const keys = { keys: [{ kid: 'old' }] };
const response = value => ({ ok: true, json: async () => value });

test('concurrent refreshes share one request; random kids cannot bypass cooldown', async () => {
  let calls = 0;
  let release;
  const f = fixture(async () => {
    calls++;
    return new Promise(resolve => { release = resolve; });
  });
  const pending = Array.from({ length: 100 }, () => f.get({ forceRefresh: true }));
  assert.equal(calls, 1);
  release(response(keys));
  await Promise.all(pending);
  await Promise.all(Array.from({ length: 100 }, () => f.get({ forceRefresh: true })));
  assert.equal(calls, 1);
  f.advance(101);
  const rotated = f.get({ forceRefresh: true });
  assert.equal(calls, 2);
  const newKeys = { keys: [{ kid: 'new' }] };
  release(response(newKeys));
  assert.deepEqual(await rotated, newKeys);
});

test('failed refreshes are throttled and expired cache fails closed', async () => {
  let calls = 0;
  const f = fixture(async () => {
    if (++calls > 1) throw new Error('offline');
    return response(keys);
  });
  await f.get();
  f.advance(101);
  await assert.rejects(f.get({ forceRefresh: true }), /offline/);
  assert.deepEqual(await f.get(), keys);
  assert.deepEqual(await f.get({ forceRefresh: true }), keys);
  assert.equal(calls, 2);
  f.advance(1000);
  await assert.rejects(f.get(), /offline/);
  await assert.rejects(f.get(), /temporarily unavailable/);
  assert.equal(calls, 3);
});

test('timeout aborts a stalled response body and releases in-flight state', async () => {
  let calls = 0;
  const f = fixture(async (_url, options) => {
    calls++;
    assert.equal(options.redirect, 'error');
    return { ok: true, json: () => new Promise((resolve, reject) => {
      options.signal.addEventListener('abort', () => reject(options.signal.reason), { once: true });
    }) };
  });
  // AbortSignal timers are unreferenced; keep the test process alive.
  const keepAlive = setInterval(() => {}, 1000);
  try {
    await assert.rejects(f.get(), { name: 'TimeoutError' });
    await assert.rejects(f.get(), /temporarily unavailable/);
    f.advance(101);
    await assert.rejects(f.get(), { name: 'TimeoutError' });
    assert.equal(calls, 2);
  } finally {
    clearInterval(keepAlive);
  }
});

test('invalid JWKS never replaces valid cached keys', async () => {
  let calls = 0;
  const f = fixture(async () => response(++calls === 1 ? keys : { keys: [] }));
  await f.get();
  f.advance(101);
  await assert.rejects(f.get({ forceRefresh: true }));
  assert.deepEqual(await f.get(), keys);
});
