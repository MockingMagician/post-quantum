'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const pq = require('../index.cjs');
const vector = require('../validation/vectors/protocol-v1.json');
const bytes = (name) => Buffer.from(vector[name], 'hex');

test('Node consumes the fixed independently generated OpenSSL v1 fixture', async () => {
  const enc = await pq.importEncryptionPrivateKey(bytes('encryptionPrivate'));
  const sig = await pq.importSigningPrivateKey(bytes('signingPrivate'));
  const ep = await pq.importEncryptionPublicKey(bytes('encryptionPublic'));
  const sp = await pq.importSigningPublicKey(bytes('signingPublic'));
  try {
    assert.deepEqual(await pq.decrypt(enc, bytes('envelope'), { aad: bytes('aad') }), bytes('message'));
    assert.equal(await pq.verify(sp, bytes('message'), bytes('signature'), { context: bytes('context') }), true);
    assert.equal(await pq.verify(sp, bytes('message'), bytes('signature'), { context: Buffer.from('wrong') }), false);
    const envelope = await pq.encrypt(ep, bytes('message'), { aad: bytes('aad') });
    assert.deepEqual(await pq.decrypt(enc, envelope, { aad: bytes('aad') }), bytes('message'));
    const signature = await pq.sign(sig, bytes('message'), { context: bytes('context') });
    assert.equal(await pq.verify(sp, bytes('message'), signature, { context: bytes('context') }), true);
  } finally {
    await Promise.all([enc.destroy(), sig.destroy()]);
  }
});
