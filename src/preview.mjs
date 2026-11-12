// Fixed local-lab preview client. See AUTHOR-CONTRACT.md for the locked contract.
//
// Security model:
//  - Every hop (initial URL and each redirect) is fully authorized BEFORE any
//    socket is opened: host rule, explicit port, and the COMPLETE resolution
//    result set must all be allowed by policy.
//  - Each socket connects to a numeric address taken from the set verified for
//    that hop. No re-resolution inside the connection path, no address reuse
//    across fetches or across hops.
//  - TLS keeps full certificate verification (rejectUnauthorized) and uses the
//    URL's DNS name for SNI/identity even when dialing a pinned IP; IP literals
//    are verified as IP identities without forged DNS SNI.
import http from 'node:http';
import https from 'node:https';
import dns from 'node:dns/promises';
import net from 'node:net';
import zlib from 'node:zlib';

const DEFAULT_LIMITS = Object.freeze({
  timeoutMs: 1000,
  maxRedirects: 3,
  maxWireBytes: 65536,
  maxDecodedBytes: 131072,
});

const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308]);

function buildLimits(provided) {
  const limits = { ...DEFAULT_LIMITS };
  if (provided != null) {
    if (typeof provided !== 'object') throw new Error('limits must be an object');
    for (const key of Object.keys(DEFAULT_LIMITS)) {
      if (provided[key] !== undefined) limits[key] = provided[key];
    }
  }
  if (!Number.isInteger(limits.timeoutMs) || limits.timeoutMs <= 0) {
    throw new Error('limits.timeoutMs must be a positive integer');
  }
  for (const key of ['maxRedirects', 'maxWireBytes', 'maxDecodedBytes']) {
    if (!Number.isInteger(limits[key]) || limits[key] < 0) {
      throw new Error(`limits.${key} must be a non-negative integer`);
    }
  }
  return limits;
}

// --- Numeric IP normalization so policy entries compare by value, not text. ---

function normalizeIPv4(address) {
  const parts = address.split('.');
  if (parts.length !== 4) return null;
  const bytes = [];
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) return null;
    const value = Number(part);
    if (value > 255) return null;
    bytes.push(value);
  }
  return bytes.join('.');
}

function normalizeIPv6(address) {
  let rest = address.toLowerCase();
  let tailGroups = [];
  const dot = rest.lastIndexOf('.');
  if (dot !== -1) {
    const colon = rest.lastIndexOf(':');
    if (colon === -1 || colon > dot) return null;
    const v4 = normalizeIPv4(rest.slice(colon + 1));
    if (!v4) return null;
    const bytes = v4.split('.').map(Number);
    tailGroups = [((bytes[0] << 8) | bytes[1]).toString(16), ((bytes[2] << 8) | bytes[3]).toString(16)];
    rest = rest.slice(0, colon);
  }
  const halves = rest.split('::');
  if (halves.length > 2) return null;
  const parse = text => {
    if (text === '' || text === undefined) return [];
    const groups = text.split(':');
    for (const group of groups) {
      if (!/^[0-9a-f]{1,4}$/.test(group)) return null;
    }
    return groups;
  };
  const left = parse(halves[0]);
  const right = parse(halves[1]);
  if (left === null || right === null) return null;
  const rightAll = right.concat(tailGroups);
  const groups = [];
  if (halves.length === 2) {
    const missing = 8 - left.length - rightAll.length;
    if (missing < 0) return null;
    groups.push(...left, ...Array(missing).fill('0'), ...rightAll);
  } else {
    groups.push(...left, ...rightAll);
  }
  if (groups.length !== 8) return null;
  return groups.map(group => parseInt(group, 16).toString(16).padStart(4, '0')).join(':');
}

// Returns { family, key } with a canonical numeric key, or null if invalid.
function normalizeIP(address) {
  if (typeof address !== 'string') return null;
  const family = net.isIP(address);
  if (family === 4) {
    const key = normalizeIPv4(address);
    return key ? { family: 4, key } : null;
  }
  if (family === 6) {
    const key = normalizeIPv6(address);
    return key ? { family: 6, key } : null;
  }
  return null;
}

// --- URL helpers ---------------------------------------------------------------

function parseUrl(raw) {
  let url;
  try {
    url = new URL(raw);
  } catch {
    throw new Error('invalid URL');
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    throw new Error('scheme not allowed');
  }
  if (url.username !== '' || url.password !== '') {
    throw new Error('credentials in URL are not allowed');
  }
  return url;
}

// Policy host key: WHATWG hostname, DNS names already lowercase, IPv6 without
// brackets.
function hostKeyOf(url) {
  let host = url.hostname;
  if (host.startsWith('[') && host.endsWith(']')) host = host.slice(1, -1);
  return host;
}

function portOf(url) {
  if (url.port !== '') return Number(url.port);
  return url.protocol === 'https:' ? 443 : 80;
}

// --- Client --------------------------------------------------------------------

export function makePreviewClient(policy = { hosts: {} }, {
  resolveAll = host => dns.lookup(host, { all: true, verbatim: true }),
  ca,
} = {}) {
  if (policy == null || typeof policy !== 'object' || policy.hosts == null || typeof policy.hosts !== 'object') {
    throw new Error('policy.hosts must be an object');
  }
  const limits = buildLimits(policy.limits);
  const hosts = policy.hosts;

  // Pre-normalize the allowed address sets once per client; policy is trusted
  // configuration and is never widened by URLs, responses, or call arguments.
  const allowedCache = new Map();
  function allowedSet(rule) {
    let set = allowedCache.get(rule);
    if (!set) {
      set = new Set();
      if (Array.isArray(rule.addresses)) {
        for (const entry of rule.addresses) {
          const norm = entry && normalizeIP(entry.address);
          if (norm && norm.family === entry.family) set.add(`${norm.family}:${norm.key}`);
        }
      }
      allowedCache.set(rule, set);
    }
    return set;
  }

  function ruleFor(hostKey) {
    if (!Object.prototype.hasOwnProperty.call(hosts, hostKey)) return undefined;
    return hosts[hostKey];
  }

  // Resolve with cancellation: an abort or the overall deadline must also cover
  // a still-pending resolver, and a late resolver result must never trigger a
  // connection.
  function resolveCancellable(host, signal) {
    return new Promise((resolve, reject) => {
      if (signal.aborted) {
        reject(new Error('operation aborted'));
        return;
      }
      const onAbort = () => reject(new Error('operation aborted'));
      signal.addEventListener('abort', onAbort, { once: true });
      let settled = false;
      const finish = (fn, value) => {
        if (settled) return;
        settled = true;
        signal.removeEventListener('abort', onAbort);
        fn(value);
      };
      Promise.resolve()
        .then(() => resolveAll(host))
        .then(
          value => {
            if (signal.aborted) return finish(reject, new Error('operation aborted'));
            finish(resolve, value);
          },
          error => finish(reject, error instanceof Error ? error : new Error(String(error))),
        );
    });
  }

  // Full per-hop authorization. Returns the verified answer list; the caller
  // must connect only to addresses from this list.
  async function verifyHop(url, signal) {
    const hostKey = hostKeyOf(url);
    const rule = ruleFor(hostKey);
    if (!rule || typeof rule !== 'object') throw new Error(`host not allowed: ${hostKey}`);
    const port = portOf(url);
    if (!Array.isArray(rule.ports) || !rule.ports.includes(port)) {
      throw new Error(`port not allowed: ${hostKey}:${port}`);
    }
    let answers;
    const literalFamily = net.isIP(hostKey);
    if (literalFamily !== 0) {
      // IP literal: no DNS, but the same address authorization applies.
      answers = [{ address: hostKey, family: literalFamily }];
    } else {
      answers = await resolveCancellable(hostKey, signal);
    }
    if (!Array.isArray(answers) || answers.length === 0) {
      throw new Error(`resolution empty for ${hostKey}`);
    }
    const allowed = allowedSet(rule);
    const verified = [];
    for (const answer of answers) {
      if (!answer || (answer.family !== 4 && answer.family !== 6)) {
        throw new Error(`invalid resolution entry for ${hostKey}`);
      }
      const norm = normalizeIP(answer.address);
      if (!norm || norm.family !== answer.family) {
        throw new Error(`resolution entry family/address mismatch for ${hostKey}`);
      }
      if (!allowed.has(`${norm.family}:${norm.key}`)) {
        throw new Error(`address not allowed for ${hostKey}: ${answer.address}`);
      }
      verified.push({ address: answer.address, family: answer.family });
    }
    return verified;
  }

  // Open one request bound to a verified address. No lookup hook is installed,
  // so the socket can only use the numeric address given here.
  function openRequest(url, verified, signal) {
    return new Promise((resolve, reject) => {
      const secure = url.protocol === 'https:';
      const transport = secure ? https : http;
      const hostKey = hostKeyOf(url);
      const target = verified[0]; // any address from this hop's verified set
      const options = {
        protocol: url.protocol,
        hostname: target.address,
        port: portOf(url),
        path: url.pathname + url.search,
        method: 'GET',
        agent: false,
        headers: { Host: url.host },
        signal,
      };
      if (secure) {
        if (ca !== undefined) options.ca = ca;
        options.rejectUnauthorized = true;
        if (net.isIP(hostKey) === 0) {
          // DNS name in URL: keep SNI and certificate identity as the DNS name
          // even though we dial the pinned numeric address.
          options.servername = hostKey;
        }
        // IP literal: no servername, certificate verified against the IP.
      }
      const req = transport.request(options, res => {
        req.removeListener('error', onError);
        resolve({ req, res });
      });
      const onError = error => reject(error instanceof Error ? error : new Error(String(error)));
      req.on('error', onError);
      req.end();
    });
  }

  // Read and decode a terminal response body, enforcing both byte budgets.
  function readBody(req, res, counters) {
    return new Promise((resolve, reject) => {
      const header = res.headers['content-encoding'];
      const encoding = (header === undefined ? 'identity' : String(header).trim().toLowerCase());
      let decoder = null;
      if (encoding === 'identity' || encoding === '') {
        decoder = null;
      } else if (encoding === 'gzip' || encoding === 'x-gzip') {
        decoder = zlib.createGunzip();
      } else if (encoding === 'deflate') {
        decoder = zlib.createInflate();
      } else if (encoding === 'br') {
        decoder = zlib.createBrotliDecompress();
      } else {
        // Unknown or stacked content encodings are rejected.
        res.destroy();
        req.destroy();
        reject(new Error(`unsupported content-encoding: ${encoding}`));
        return;
      }

      const chunks = [];
      let settled = false;
      let resEnded = false;
      const fail = error => {
        if (settled) return;
        settled = true;
        res.destroy();
        if (decoder) decoder.destroy();
        req.destroy();
        reject(error instanceof Error ? error : new Error(String(error)));
      };

      res.on('data', chunk => {
        counters.wire += chunk.length;
        if (counters.wire > limits.maxWireBytes) fail(new Error('wire byte limit exceeded'));
      });
      res.on('error', fail);
      res.on('aborted', () => fail(new Error('response aborted')));
      res.on('end', () => { resEnded = true; });
      res.on('close', () => {
        if (!settled && !resEnded) fail(new Error('response closed before completion'));
      });

      const out = decoder || res;
      if (decoder) {
        res.pipe(decoder);
        decoder.on('error', fail);
      }
      out.on('data', chunk => {
        counters.decoded += chunk.length;
        if (counters.decoded > limits.maxDecodedBytes) {
          fail(new Error('decoded byte limit exceeded'));
          return;
        }
        chunks.push(chunk);
      });
      out.on('end', () => {
        if (settled) return;
        settled = true;
        resolve(Buffer.concat(chunks));
      });
    });
  }

  async function fetchPreview(raw, { signal } = {}) {
    if (signal !== undefined && signal !== null && typeof signal.aborted !== 'boolean') {
      throw new Error('signal must be an AbortSignal');
    }
    // Per-fetch state: deadline timer, abort wiring, byte counters and verified
    // addresses are all local to this call and never shared across fetches.
    const controller = new AbortController();
    let abortReason = null;
    const abortWith = reason => {
      if (!abortReason) abortReason = reason;
      controller.abort();
    };
    const onExternalAbort = () => {
      const reason = signal && signal.reason;
      abortWith(reason instanceof Error ? reason : new Error('operation aborted'));
    };
    if (signal) {
      if (signal.aborted) onExternalAbort();
      else signal.addEventListener('abort', onExternalAbort, { once: true });
    }
    // One total deadline from function entry to completed decode, covering
    // resolution, connection, every redirect hop and the body read.
    const timer = setTimeout(() => abortWith(new Error('fetch timeout')),
      Math.min(limits.timeoutMs, 2 ** 31 - 1));

    try {
      let url = parseUrl(raw);
      const counters = { wire: 0, decoded: 0 };
      let followed = 0;
      for (;;) {
        if (controller.signal.aborted) throw abortReason;
        // Authorize this hop completely before opening any socket.
        const verified = await verifyHop(url, controller.signal);
        if (controller.signal.aborted) throw abortReason;
        const { req, res } = await openRequest(url, verified, controller.signal);
        const location = res.headers.location;
        if (REDIRECT_STATUSES.has(res.statusCode) && location !== undefined) {
          // Close the redirect response immediately; nothing read, nothing
          // counted. The next hop is re-authorized from scratch.
          res.destroy();
          req.destroy();
          if (followed >= limits.maxRedirects) {
            throw new Error('redirect limit exceeded');
          }
          followed += 1;
          let next;
          try {
            next = new URL(location, url);
          } catch {
            throw new Error('invalid redirect location');
          }
          url = parseUrl(next.href);
          continue;
        }
        const body = await readBody(req, res, counters);
        return { url: url.href, status: res.statusCode, body };
      }
    } catch (error) {
      if (abortReason) throw abortReason;
      throw error instanceof Error ? error : new Error(String(error));
    } finally {
      clearTimeout(timer);
      if (signal) signal.removeEventListener('abort', onExternalAbort);
    }
  }

  return { fetchPreview };
}
