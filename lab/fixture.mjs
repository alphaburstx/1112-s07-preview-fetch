import http from 'node:http';
import https from 'node:https';
import { gzipSync, deflateSync, brotliCompressSync } from 'node:zlib';
import { makeTemporaryTLS } from './tls.mjs';

const listen = (server, host, port = 0) => new Promise((resolve, reject) => {
  server.once('error', reject);
  server.listen({ host, port, ipv6Only: host === '::1' }, () => {
    server.removeListener('error', reject);
    resolve(server.address().port);
  });
});

export async function createLab() {
  const tls = await makeTemporaryTLS();
  const logs = [], connections = [], sockets = new Set(), servers = [];
  const compress = { gzip: gzipSync, deflate: deflateSync, br: brotliCompressSync };

  function handler(id) {
    return (req, res) => {
      const u = new URL(req.url, 'http://fixture.test');
      const event = { id, host: req.headers.host, url: req.url,
        sni: req.socket.servername || null, remoteAddress: req.socket.remoteAddress,
        at: Date.now(), closed: false };
      logs.push(event);
      const timers = new Set();
      const later = (fn, ms) => { const timer = setTimeout(fn, ms); timers.add(timer); return timer; };
      res.once('close', () => { event.closed = true; for (const timer of timers) clearTimeout(timer); });
      if (u.pathname === '/never') return;
      if (u.pathname === '/redirect' || u.pathname === '/delay-redirect') {
        const send = () => { res.writeHead(Number(u.searchParams.get('status') || 302),
          { location: u.searchParams.get('to') || '/ok' }); res.end('redirect'); };
        if (u.pathname === '/delay-redirect') later(send, Number(u.searchParams.get('ms') || 50));
        else send();
        return;
      }
      if (u.pathname === '/chain') {
        const n = Number(u.searchParams.get('n') || 0);
        if (n > 0) { u.searchParams.set('n', String(n - 1));
          res.writeHead(302, { location: u.pathname + u.search }); res.end(); }
        else res.end('chain-done');
        return;
      }
      if (u.pathname === '/trickle') {
        let sent = 0;
        const size = Number(u.searchParams.get('n') || 20);
        const every = Number(u.searchParams.get('every') || 30);
        res.writeHead(200, { 'content-type': 'application/octet-stream' });
        const tick = () => { if (res.destroyed) return; res.write('x');
          if (++sent === size) res.end(); else later(tick, every); };
        tick();
        return;
      }
      if (u.pathname === '/echo') {
        res.setHeader('content-type', 'application/json');
        res.end(JSON.stringify({ id, host: event.host, url: req.url, sni: event.sni }));
        return;
      }
      let body;
      if (u.pathname === '/bytes' || u.pathname === '/random') {
        body = Buffer.alloc(Number(u.searchParams.get('n') || 0), 120);
        if (u.pathname === '/random') {
          let state = 123456789;
          for (let i = 0; i < body.length; i++) {
            state ^= state << 13; state ^= state >>> 17; state ^= state << 5; body[i] = state & 255;
          }
        }
      } else if (u.pathname === '/broken') body = Buffer.from('not a valid compressed stream');
      else body = Buffer.from(`ok:${id}:${u.searchParams.get('text') || 'resource'}`);
      const encoding = u.searchParams.get('encoding');
      if (encoding && encoding !== 'identity') {
        res.setHeader('content-encoding', encoding);
        if (u.pathname !== '/broken' && compress[encoding]) body = compress[encoding](body);
      }
      const finish = () => { if (!res.destroyed) { res.writeHead(200); res.end(body); } };
      if (u.pathname === '/delay') later(finish, Number(u.searchParams.get('ms') || 50));
      else finish();
    };
  }
  function server(secure, id) {
    const result = secure ? https.createServer({ key: tls.key, cert: tls.cert }, handler(id)) : http.createServer(handler(id));
    result.on('connection', socket => {
      sockets.add(socket);
      connections.push({ id, at: Date.now(), address: socket.localAddress });
      socket.once('close', () => sockets.delete(socket));
    });
    result.on('tlsClientError', () => {});
    servers.push(result);
    return result;
  }
  try {
    const httpPort = await listen(server(false, 'http4'), '127.0.0.1');
    await listen(server(false, 'http6'), '::1', httpPort);
    const httpsPort = await listen(server(true, 'https4'), '127.0.0.1');
    await listen(server(true, 'https6'), '::1', httpsPort);
    return {
      httpPort, httpsPort, ca: tls.ca, logs, connections,
      origin: (host = 'preview.test', secure = false) => `${secure ? 'https' : 'http'}://${host}:${secure ? httpsPort : httpPort}`,
      resolveAll: async () => [{ address: '127.0.0.1', family: 4 }],
      close: async () => {
        for (const socket of sockets) socket.destroy();
        await Promise.all(servers.map(s => new Promise(resolve => s.close(resolve))));
        await tls.cleanup();
      }
    };
  } catch (error) {
    for (const socket of sockets) socket.destroy();
    await Promise.all(servers.map(s => new Promise(resolve => s.close(resolve))));
    await tls.cleanup();
    throw error;
  }
}
