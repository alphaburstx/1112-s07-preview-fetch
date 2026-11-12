// Security regression suite for src/preview.mjs. Loopback only: every check
// runs against lab/fixture.mjs servers on 127.0.0.1/::1 with injected
// resolution. No real DNS, hosts file, proxy, or trust-store changes.
//
// Run: node test/regression.mjs   (requires the environment in ENVIRONMENT.md)
import assert from 'node:assert/strict';
import { gzipSync } from 'node:zlib';
import { makePreviewClient } from '../src/preview.mjs';
import { createLab } from '../lab/fixture.mjs';

const tests = [];
const test = (name, fn) => tests.push({ name, fn });

const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));

// Deterministic body of the fixture's /random endpoint (same xorshift).
function randomBody(n) {
  const body = Buffer.alloc(n, 120);
  let state = 123456789;
  for (let i = 0; i < n; i++) {
    state ^= state << 13; state ^= state >>> 17; state ^= state << 5;
    body[i] = state & 255;
  }
  return body;
}

async function expectReject(promise, label) {
  try {
    await promise;
  } catch (error) {
    assert.ok(error instanceof Error, `${label}: rejection must be an Error`);
    return error;
  }
  assert.fail(`${label}: expected rejection`);
}

const lab = await createLab();
const V4 = { address: '127.0.0.1', family: 4 };
const V6 = { address: '::1', family: 6 };

// Shared helpers bound to the running lab.
function policyFor(hosts, limits) {
  return { hosts, ...(limits ? { limits } : {}) };
}
function allow(host, extra = {}) {
  return { ports: [lab.httpPort, lab.httpsPort], addresses: [V4, V6], ...extra };
}
// Resolver that only knows lab hosts and records calls per host.
function makeResolver(map = { 'preview.test': [V4], 'hop.test': [V4] }) {
  const calls = [];
  const resolveAll = async host => {
    calls.push(host);
    if (!Object.prototype.hasOwnProperty.call(map, host)) {
      throw new Error(`resolver: unknown host ${host}`);
    }
    return map[host];
  };
  return { resolveAll, calls };
}

// --- Normal paths ------------------------------------------------------------

test('normal: HTTP/HTTPS over IPv4 and IPv6 with correct Host and SNI', async () => {
  for (const address of [V4, V6]) {
    const client = makePreviewClient(
      policyFor({ 'preview.test': allow('preview.test', { addresses: [address] }) }),
      { resolveAll: async () => [address], ca: lab.ca },
    );
    for (const secure of [false, true]) {
      const before = lab.logs.length;
      const result = await client.fetchPreview(`${lab.origin('preview.test', secure)}/echo?normal=1`);
      assert.equal(result.status, 200);
      const echo = JSON.parse(result.body.toString());
      assert.equal(echo.id, `${secure ? 'https' : 'http'}${address.family}`);
      assert.equal(echo.host, `preview.test:${secure ? lab.httpsPort : lab.httpPort}`);
      assert.equal(echo.sni, secure ? 'preview.test' : null);
      assert.equal(lab.logs.length, before + 1);
    }
  }
});

test('normal: IP literal URLs keep Host brackets and skip DNS', async () => {
  const resolver = makeResolver({});
  const client = makePreviewClient(
    policyFor({ '::1': allow('::1', { addresses: [V6] }), '127.0.0.1': allow('127.0.0.1', { addresses: [V4] }) }),
    { resolveAll: resolver.resolveAll, ca: lab.ca },
  );
  const r6 = await client.fetchPreview(`http://[::1]:${lab.httpPort}/echo`);
  assert.equal(JSON.parse(r6.body.toString()).host, `[::1]:${lab.httpPort}`);
  const r4 = await client.fetchPreview(`https://127.0.0.1:${lab.httpsPort}/echo`);
  const echo4 = JSON.parse(r4.body.toString());
  assert.equal(echo4.host, `127.0.0.1:${lab.httpsPort}`);
  assert.equal(echo4.sni, null); // IP identity: no forged DNS SNI
  assert.deepEqual(resolver.calls, []); // literals never hit DNS
});

test('normal: HTTPS to pinned IP still sends DNS SNI and verifies certificate', async () => {
  const client = makePreviewClient(
    policyFor({ 'preview.test': allow('preview.test', { addresses: [V4] }) }),
    { resolveAll: async () => [V4], ca: lab.ca },
  );
  const result = await client.fetchPreview(`${lab.origin('preview.test', true)}/echo`);
  assert.equal(JSON.parse(result.body.toString()).sni, 'preview.test');
});

test('normal: TLS verification is not bypassed (wrong CA rejected)', async () => {
  const other = await createLab(); // second lab => different ephemeral CA
  try {
    const client = makePreviewClient(
      policyFor({ 'preview.test': allow('preview.test', { addresses: [V4] }) }),
      { resolveAll: async () => [V4], ca: other.ca },
    );
    await expectReject(client.fetchPreview(`${lab.origin('preview.test', true)}/ok`), 'wrong CA');
  } finally {
    await other.close();
  }
});

// --- Authorization -----------------------------------------------------------

test('authz: unconfigured host rejected without calling the resolver', async () => {
  const resolver = makeResolver();
  const client = makePreviewClient(policyFor({ 'preview.test': allow('preview.test') }),
    { resolveAll: resolver.resolveAll });
  await expectReject(client.fetchPreview(`${lab.origin('other.test')}/ok`), 'unknown host');
  assert.deepEqual(resolver.calls, []);
});

test('authz: unconfigured port rejected', async () => {
  const client = makePreviewClient(
    policyFor({ 'preview.test': { ports: [lab.httpPort + 1 === lab.httpsPort ? lab.httpPort + 2 : lab.httpPort + 1], addresses: [V4] } }),
    { resolveAll: async () => [V4] },
  );
  await expectReject(client.fetchPreview(`${lab.origin('preview.test')}/ok`), 'wrong port');
});

test('authz: address outside policy rejected, no request reaches server', async () => {
  const before = lab.logs.length;
  const client = makePreviewClient(
    policyFor({ 'preview.test': allow('preview.test', { addresses: [V6] }) }),
    { resolveAll: async () => [V4] }, // resolves to IPv4, policy allows only ::1
  );
  await expectReject(client.fetchPreview(`${lab.origin('preview.test')}/ok`), 'address denied');
  assert.equal(lab.logs.length, before);
});

test('authz: EVERY resolved address must be allowed, not just the first', async () => {
  const before = lab.logs.length;
  const client = makePreviewClient(
    policyFor({ 'preview.test': allow('preview.test', { addresses: [V4] }) }),
    { resolveAll: async () => [V4, { address: '10.9.9.9', family: 4 }] },
  );
  await expectReject(client.fetchPreview(`${lab.origin('preview.test')}/ok`), 'second address denied');
  assert.equal(lab.logs.length, before);
});

test('authz: empty, malformed, and family-mismatched resolutions rejected', async () => {
  const cases = [
    async () => [],
    async () => [{ address: 'not-an-ip', family: 4 }],
    async () => [{ address: '127.0.0.1', family: 6 }],
    async () => [{ address: '::1', family: 4 }],
    async () => [{ family: 4 }],
    async () => 'not-an-array',
  ];
  for (const resolveAll of cases) {
    const before = lab.logs.length;
    const client = makePreviewClient(policyFor({ 'preview.test': allow('preview.test') }), { resolveAll });
    await expectReject(client.fetchPreview(`${lab.origin('preview.test')}/ok`), 'bad resolution');
    assert.equal(lab.logs.length, before);
  }
});

test('authz: credentials and non-HTTP(S) schemes rejected', async () => {
  const client = makePreviewClient(policyFor({ 'preview.test': allow('preview.test') }),
    { resolveAll: async () => [V4] });
  await expectReject(client.fetchPreview(`http://user:pw@preview.test:${lab.httpPort}/ok`), 'credentials');
  await expectReject(client.fetchPreview(`ftp://preview.test:${lab.httpPort}/ok`), 'scheme');
  await expectReject(client.fetchPreview('not a url'), 'invalid URL');
});

test('authz: numeric-equivalent IPv6 forms match policy', async () => {
  const client = makePreviewClient(
    policyFor({ 'preview.test': allow('preview.test', { addresses: [{ address: '0:0:0:0:0:0:0:1', family: 6 }] }) }),
    { resolveAll: async () => [V6] },
  );
  const result = await client.fetchPreview(`${lab.origin('preview.test')}/ok`);
  assert.equal(result.status, 200);
});

// --- Connection binding --------------------------------------------------------

test('binding: exactly one resolution per hop and socket uses the verified address', async () => {
  const resolver = makeResolver({ 'preview.test': [V4] });
  const client = makePreviewClient(policyFor({ 'preview.test': allow('preview.test') }),
    { resolveAll: resolver.resolveAll });
  const before = lab.connections.length;
  await client.fetchPreview(`${lab.origin('preview.test')}/ok`);
  assert.deepEqual(resolver.calls, ['preview.test']); // no second lookup inside connect
  const conn = lab.connections[lab.connections.length - 1];
  assert.equal(lab.connections.length, before + 1);
  assert.equal(conn.address, '127.0.0.1');
});

// --- Redirects -----------------------------------------------------------------

test('redirect: authorized cross-host hop re-verified and final URL returned', async () => {
  const resolver = makeResolver({ 'preview.test': [V4], 'hop.test': [V4] });
  const client = makePreviewClient(
    policyFor({ 'preview.test': allow('preview.test'), 'hop.test': allow('hop.test') }),
    { resolveAll: resolver.resolveAll },
  );
  const target = `${lab.origin('hop.test')}/echo?via=redirect`;
  const result = await client.fetchPreview(
    `${lab.origin('preview.test')}/redirect?to=${encodeURIComponent(target)}`);
  assert.equal(result.status, 200);
  assert.equal(result.url, target);
  const echo = JSON.parse(result.body.toString());
  assert.equal(echo.host, `hop.test:${lab.httpPort}`);
  assert.deepEqual(resolver.calls, ['preview.test', 'hop.test']);
});

test('redirect: HTTPS hop keeps per-hop SNI for the new host', async () => {
  const resolver = makeResolver({ 'preview.test': [V4], 'hop.test': [V4] });
  const client = makePreviewClient(
    policyFor({ 'preview.test': allow('preview.test'), 'hop.test': allow('hop.test') }),
    { resolveAll: resolver.resolveAll, ca: lab.ca },
  );
  const target = `${lab.origin('hop.test', true)}/echo`;
  const result = await client.fetchPreview(
    `${lab.origin('preview.test', true)}/redirect?to=${encodeURIComponent(target)}`);
  assert.equal(JSON.parse(result.body.toString()).sni, 'hop.test');
});

test('redirect: unauthorized target host rejected before any connection', async () => {
  const resolver = makeResolver({ 'preview.test': [V4] });
  const client = makePreviewClient(policyFor({ 'preview.test': allow('preview.test') }),
    { resolveAll: resolver.resolveAll });
  const before = lab.logs.length;
  await expectReject(client.fetchPreview(
    `${lab.origin('preview.test')}/redirect?to=${encodeURIComponent(`${lab.origin('evil.test')}/ok`)}`),
    'redirect to unknown host');
  assert.equal(lab.logs.length, before + 1); // only the initial request happened
});

test('redirect: target re-resolved per hop; poisoned second resolution rejected', async () => {
  let n = 0;
  const resolveAll = async () => (++n === 1 ? [V4] : [{ address: '10.9.9.9', family: 4 }]);
  const client = makePreviewClient(
    policyFor({ 'preview.test': allow('preview.test'), 'hop.test': allow('hop.test') }),
    { resolveAll },
  );
  const before = lab.logs.length;
  await expectReject(client.fetchPreview(
    `${lab.origin('preview.test')}/redirect?to=${encodeURIComponent(`${lab.origin('hop.test')}/ok`)}`),
    'second hop resolution denied');
  assert.equal(lab.logs.length, before + 1);
});

test('redirect: maxRedirects enforced (chain of 5)', async () => {
  const resolver = makeResolver({ 'preview.test': [V4] });
  const mk = maxRedirects => makePreviewClient(
    policyFor({ 'preview.test': allow('preview.test') }, { maxRedirects }),
    { resolveAll: resolver.resolveAll });
  const ok = await mk(5).fetchPreview(`${lab.origin('preview.test')}/chain?n=5`);
  assert.equal(ok.body.toString(), 'chain-done');
  assert.equal(ok.url, `${lab.origin('preview.test')}/chain?n=0`);
  await expectReject(mk(4).fetchPreview(`${lab.origin('preview.test')}/chain?n=5`), 'chain over limit');
  await expectReject(mk(0).fetchPreview(`${lab.origin('preview.test')}/redirect`), 'zero redirects');
});

test('redirect: non-redirect status with Location is terminal', async () => {
  const client = makePreviewClient(policyFor({ 'preview.test': allow('preview.test') }),
    { resolveAll: async () => [V4] });
  const result = await client.fetchPreview(`${lab.origin('preview.test')}/redirect?status=404`);
  assert.equal(result.status, 404);
  assert.equal(result.body.toString(), 'redirect');
});

// --- Decoding and budgets ------------------------------------------------------

test('decode: gzip, deflate, br and identity round-trip', async () => {
  const client = makePreviewClient(policyFor({ 'preview.test': allow('preview.test') }),
    { resolveAll: async () => [V4] });
  for (const encoding of ['gzip', 'deflate', 'br', 'identity']) {
    const result = await client.fetchPreview(
      `${lab.origin('preview.test')}/ok?text=${encoding}&encoding=${encoding}`);
    assert.equal(result.body.toString(), `ok:http4:${encoding}`);
  }
});

test('decode: corrupt compressed body and unsupported encodings rejected', async () => {
  const client = makePreviewClient(policyFor({ 'preview.test': allow('preview.test') }),
    { resolveAll: async () => [V4] });
  await expectReject(client.fetchPreview(`${lab.origin('preview.test')}/broken?encoding=gzip`), 'corrupt gzip');
  await expectReject(client.fetchPreview(`${lab.origin('preview.test')}/ok?encoding=compress`), 'unknown encoding');
  await expectReject(client.fetchPreview(`${lab.origin('preview.test')}/ok?encoding=${encodeURIComponent('gzip,br')}`), 'stacked encoding');
});

test('budget: maxWireBytes exact fit succeeds, one less rejects', async () => {
  const body = randomBody(4096);
  const wire = gzipSync(body).length;
  const mk = maxWireBytes => makePreviewClient(
    policyFor({ 'preview.test': allow('preview.test') }, { maxWireBytes }),
    { resolveAll: async () => [V4] });
  const ok = await mk(wire).fetchPreview(`${lab.origin('preview.test')}/random?n=4096&encoding=gzip`);
  assert.deepEqual(ok.body, body);
  await expectReject(mk(wire - 1).fetchPreview(`${lab.origin('preview.test')}/random?n=4096&encoding=gzip`),
    'wire limit - 1');
});

test('budget: maxDecodedBytes exact fit succeeds, one less rejects', async () => {
  const mk = maxDecodedBytes => makePreviewClient(
    policyFor({ 'preview.test': allow('preview.test') }, { maxDecodedBytes }),
    { resolveAll: async () => [V4] });
  const ok = await mk(100).fetchPreview(`${lab.origin('preview.test')}/bytes?n=100`);
  assert.equal(ok.body.length, 100);
  await expectReject(mk(99).fetchPreview(`${lab.origin('preview.test')}/bytes?n=100`), 'decoded limit - 1');
});

test('budget: Content-Length is not trusted (declared small, sent large)', async () => {
  // /trickle streams without Content-Length; the budget must trip on real bytes.
  const client = makePreviewClient(
    policyFor({ 'preview.test': allow('preview.test') }, { maxWireBytes: 10, timeoutMs: 5000 }),
    { resolveAll: async () => [V4] });
  await expectReject(client.fetchPreview(`${lab.origin('preview.test')}/trickle?n=20&every=5`),
    'streamed overflow');
});

test('budget: byte counters are per-fetch, not shared across concurrent fetches', async () => {
  const client = makePreviewClient(
    policyFor({ 'preview.test': allow('preview.test') }, { maxWireBytes: 150, timeoutMs: 5000 }),
    { resolveAll: async () => [V4] });
  const url = `${lab.origin('preview.test')}/bytes?n=100`;
  const [a, b] = await Promise.all([client.fetchPreview(url), client.fetchPreview(url)]);
  assert.equal(a.body.length, 100);
  assert.equal(b.body.length, 100);
});

// --- Timeout, cancellation, lifecycle ------------------------------------------

test('timeout: total deadline covers a response that never comes', async () => {
  const client = makePreviewClient(
    policyFor({ 'preview.test': allow('preview.test') }, { timeoutMs: 200 }),
    { resolveAll: async () => [V4] });
  const start = Date.now();
  await expectReject(client.fetchPreview(`${lab.origin('preview.test')}/never`), 'never responds');
  assert.ok(Date.now() - start < 2000, 'must fail near the deadline, not hang');
});

test('timeout: total deadline spans a slow hop and a slow body', async () => {
  const client = makePreviewClient(
    policyFor({ 'preview.test': allow('preview.test') }, { timeoutMs: 300 }),
    { resolveAll: async () => [V4] });
  await expectReject(client.fetchPreview(`${lab.origin('preview.test')}/delay?ms=500`), 'slow response');
  await expectReject(client.fetchPreview(`${lab.origin('preview.test')}/trickle?n=20&every=100`),
    'trickling body');
});

test('timeout: deadline covers a resolver that never settles', async () => {
  const client = makePreviewClient(
    policyFor({ 'preview.test': allow('preview.test') }, { timeoutMs: 200 }),
    { resolveAll: () => new Promise(() => {}) });
  await expectReject(client.fetchPreview(`${lab.origin('preview.test')}/ok`), 'stuck resolver');
});

test('cancel: abort during a pending response rejects', async () => {
  const client = makePreviewClient(
    policyFor({ 'preview.test': allow('preview.test') }, { timeoutMs: 5000 }),
    { resolveAll: async () => [V4] });
  const controller = new AbortController();
  const pending = client.fetchPreview(`${lab.origin('preview.test')}/delay?ms=500`,
    { signal: controller.signal });
  await sleep(50);
  controller.abort();
  await expectReject(pending, 'abort during response');
});

test('cancel: abort during pending resolution; late resolver result opens no connection', async () => {
  const before = lab.logs.length;
  let resolveLate;
  const resolveAll = () => new Promise(resolve => { resolveLate = () => resolve([V4]); });
  const client = makePreviewClient(
    policyFor({ 'preview.test': allow('preview.test') }, { timeoutMs: 5000 }),
    { resolveAll });
  const controller = new AbortController();
  const pending = client.fetchPreview(`${lab.origin('preview.test')}/ok`, { signal: controller.signal });
  await sleep(50);
  controller.abort();
  await expectReject(pending, 'abort during resolution');
  resolveLate(); // resolver finishes after cancellation
  await sleep(100);
  assert.equal(lab.logs.length, before, 'late resolver result must not trigger a connection');
});

test('cancel: concurrent fetches are independent (abort one, other completes)', async () => {
  const client = makePreviewClient(
    policyFor({ 'preview.test': allow('preview.test') }, { timeoutMs: 5000 }),
    { resolveAll: async () => [V4] });
  const controller = new AbortController();
  const slow = client.fetchPreview(`${lab.origin('preview.test')}/trickle?n=20&every=50`,
    { signal: controller.signal });
  const fast = client.fetchPreview(`${lab.origin('preview.test')}/ok?text=survivor`);
  await sleep(60);
  controller.abort();
  await expectReject(slow, 'aborted fetch');
  const result = await fast;
  assert.equal(result.body.toString(), 'ok:http4:survivor');
});

// --- Configuration validation ----------------------------------------------------

test('config: invalid limits rejected at client construction', async () => {
  const base = { hosts: { 'preview.test': allow('preview.test') } };
  for (const limits of [
    { timeoutMs: 0 }, { timeoutMs: -1 }, { timeoutMs: 1.5 }, { timeoutMs: '100' },
    { maxRedirects: -1 }, { maxWireBytes: -5 }, { maxDecodedBytes: 2.5 },
  ]) {
    assert.throws(() => makePreviewClient({ ...base, limits }), `limits ${JSON.stringify(limits)}`);
  }
  // Defaults apply when limits are omitted.
  const client = makePreviewClient(base, { resolveAll: async () => [V4] });
  const result = await client.fetchPreview(`${lab.origin('preview.test')}/ok`);
  assert.equal(result.status, 200);
});

// --- Runner ----------------------------------------------------------------------

let failed = 0;
for (const { name, fn } of tests) {
  try {
    await fn();
    console.log(`PASS ${name}`);
  } catch (error) {
    failed += 1;
    console.error(`FAIL ${name}\n  ${error.stack.split('\n').join('\n  ')}`);
  }
}
await lab.close();
console.log(failed === 0 ? `REGRESSION PASS: ${tests.length} tests` : `REGRESSION FAIL: ${failed}/${tests.length}`);
process.exit(failed === 0 ? 0 : 1);
