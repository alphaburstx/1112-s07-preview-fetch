import { mkdtemp, readFile, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

const run = promisify(execFile);

// Runtime-only synthetic CA and keys. Nothing is installed in a trust store.
export async function makeTemporaryTLS() {
  const dir = await mkdtemp(path.join(tmpdir(), 's07-tls-'));
  const openssl = process.env.S07_OPENSSL || 'openssl';
  const file = name => path.join(dir, name);
  const command = args => run(openssl, args, { timeout: 15000, maxBuffer: 1024 * 1024 });
  try {
    await command(['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-sha256', '-days', '1',
      '-subj', '/CN=S07 ephemeral local test CA', '-keyout', file('ca.key'), '-out', file('ca.pem'),
      '-addext', 'basicConstraints=critical,CA:TRUE', '-addext', 'keyUsage=critical,keyCertSign,cRLSign']);
    await command(['req', '-new', '-newkey', 'rsa:2048', '-nodes', '-sha256',
      '-subj', '/CN=preview.test', '-keyout', file('server.key'), '-out', file('server.csr')]);
    await writeFile(file('server.ext'), [
      'basicConstraints=critical,CA:FALSE',
      'keyUsage=critical,digitalSignature,keyEncipherment',
      'extendedKeyUsage=serverAuth',
      'subjectAltName=DNS:preview.test,DNS:hop.test,DNS:alpha.test,DNS:beta.test,IP:127.0.0.1,IP:::1', ''
    ].join('\n'));
    await command(['x509', '-req', '-in', file('server.csr'), '-CA', file('ca.pem'),
      '-CAkey', file('ca.key'), '-CAcreateserial', '-days', '1', '-sha256',
      '-extfile', file('server.ext'), '-out', file('server.pem')]);
    return {
      ca: await readFile(file('ca.pem')),
      key: await readFile(file('server.key')),
      cert: await readFile(file('server.pem')),
      cleanup: () => rm(dir, { recursive: true, force: true }),
    };
  } catch (error) {
    await rm(dir, { recursive: true, force: true });
    throw error;
  }
}
