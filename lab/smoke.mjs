import assert from 'node:assert/strict';
import { makePreviewClient } from '../src/preview.mjs';
import { createLab } from './fixture.mjs';

const lab = await createLab();
try {
  for (const address of [{ address: '127.0.0.1', family: 4 }, { address: '::1', family: 6 }]) {
    const policy = { hosts: { 'preview.test': {
      ports: [lab.httpPort, lab.httpsPort], addresses: [address]
    } } };
    const client = makePreviewClient(policy, { resolveAll: async () => [address], ca: lab.ca });
    for (const secure of [false, true]) {
      const url = `${lab.origin('preview.test', secure)}/echo?normal=1`;
      const result = await client.fetchPreview(url);
      assert.equal(result.status, 200);
      const echo = JSON.parse(result.body.toString());
      assert.equal(echo.id, `${secure ? 'https' : 'http'}${address.family}`);
      assert.equal(echo.host, `preview.test:${secure ? lab.httpsPort : lab.httpPort}`);
      if (secure) assert.equal(echo.sni, 'preview.test');
      console.log(JSON.stringify({ protocol: secure ? 'HTTPS' : 'HTTP', family: address.family, ok: true, echo }));
    }
  }
  assert.equal(lab.logs.length, 4);
  console.log('SMOKE PASS: server confirmed HTTP/HTTPS on IPv4/IPv6');
} finally { await lab.close(); }
