'use strict';
// Test-only bridge. Private seeds supplied by tests are intentionally public.
const fs = require('node:fs');
const pq = require('../index.cjs');
const input = JSON.parse(fs.readFileSync(0, 'utf8'));
const bytes = (field) => Buffer.from(input[field], 'hex');
(async () => {
  const enc = await pq.importEncryptionPrivateKey(bytes('encryptionPrivate'));
  const sig = await pq.importSigningPrivateKey(bytes('signingPrivate'));
  const ep = await pq.importEncryptionPublicKey(bytes('encryptionPublic'));
  const sp = await pq.importSigningPublicKey(bytes('signingPublic'));
  let result;
  try {
    if (input.op === 'produce') {
      result = {
        encryptionPublic: (await ep.export()).toString('hex'),
        signingPublic: (await sp.export()).toString('hex'),
        envelope: (await pq.encrypt(ep, bytes('message'), { aad: bytes('aad') })).toString('hex'),
        signature: (await pq.sign(sig, bytes('message'), { context: bytes('context') })).toString('hex'),
      };
    } else {
      result = {
        plaintext: (await pq.decrypt(enc, bytes('envelope'), { aad: bytes('aad') })).toString('hex'),
        valid: await pq.verify(sp, bytes('message'), bytes('signature'), { context: bytes('context') }),
      };
    }
  } finally {
    await Promise.all([enc.destroy(), sig.destroy()]);
  }
  process.stdout.write(JSON.stringify(result));
})().catch((e) => { console.error(e); process.exitCode = 1; });
