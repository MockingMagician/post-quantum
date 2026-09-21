'use strict';
const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const { Worker } = require('node:worker_threads');
const pq = require('../index.cjs');
let enc, sig;
before(async () => { [enc, sig] = await Promise.all([pq.generateEncryptionKeyPair(), pq.generateSigningKeyPair()]); });
after(async () => { await Promise.all([enc.privateKey.destroy(), sig.privateKey.destroy()]); });
const message = Buffer.from('Bonjour — quantum\0\xff');
const aad = Buffer.from('tenant:7/message:42');
const context = Buffer.from('application/v1');
const rejectsCode = (promise, code) => assert.rejects(promise, { code });

test('CJS and ESM expose the same native API', async () => {
  const esm = await import('../index.mjs');
  for (const name of Object.keys(pq)) assert.equal(esm[name], pq[name], name);
  assert.equal(pq.MAX_MESSAGE_LEN, 16 * 1024 * 1024);
  assert.equal(pq.MAX_ENVELOPE_LEN, pq.MAX_MESSAGE_LEN + 1606);
});

test('encryption authenticates message, recipient and associated data', async () => {
  const encrypted = await pq.encrypt(enc.publicKey, message, { aad });
  assert.deepEqual(await pq.decrypt(enc.privateKey, encrypted, { aad }), message);
  assert.notDeepEqual(encrypted, await pq.encrypt(enc.publicKey, message, { aad }));
  await rejectsCode(pq.decrypt(enc.privateKey, encrypted), 'ERR_AUTHENTICATION_FAILED');
  const other = await pq.generateEncryptionKeyPair();
  try { await rejectsCode(pq.decrypt(other.privateKey, encrypted, { aad }), 'ERR_AUTHENTICATION_FAILED'); }
  finally { await other.privateKey.destroy(); }
  for (const offset of [10, 1578, encrypted.length - 17, encrypted.length - 1]) {
    const corrupt = Buffer.from(encrypted); corrupt[offset] ^= 1;
    await rejectsCode(pq.decrypt(enc.privateKey, corrupt, { aad }), 'ERR_AUTHENTICATION_FAILED');
  }
});

test('signatures bind the message, key and context and use fresh randomness', async () => {
  const signature = await pq.sign(sig.privateKey, message, { context });
  assert.equal(signature.length, 4637);
  assert.equal(await pq.verify(sig.publicKey, message, signature, { context }), true);
  assert.notDeepEqual(signature, await pq.sign(sig.privateKey, message, { context }));
  assert.equal(await pq.verify(sig.publicKey, message, signature), false);
  assert.equal(await pq.verify(sig.publicKey, Buffer.from('wrong'), signature, { context }), false);
  const other = await pq.generateSigningKeyPair();
  try { assert.equal(await pq.verify(other.publicKey, message, signature, { context }), false); }
  finally { await other.privateKey.destroy(); }
  for (const bytes of [Buffer.alloc(0), signature.subarray(0, -1), Buffer.concat([signature, Buffer.of(0)]), Buffer.alloc(10000)]) {
    assert.equal(await pq.verify(sig.publicKey, message, bytes, { context }), false);
  }
  for (const offset of [0, 4, 5, 6, 10, signature.length - 1]) {
    const corrupt = Buffer.from(signature); corrupt[offset] ^= 1;
    assert.equal(await pq.verify(sig.publicKey, message, corrupt, { context }), false);
  }
});

test('empty messages, sliced Uint8Array and zero-length contexts work', async () => {
  for (const bytes of [new Uint8Array(0), new Uint8Array([8, 1, 2, 9]).subarray(1, 3)]) {
    const encrypted = await pq.encrypt(enc.publicKey, bytes);
    assert.deepEqual(await pq.decrypt(enc.privateKey, encrypted), Buffer.from(bytes));
    const signature = await pq.sign(sig.privateKey, bytes, { context: new Uint8Array(0) });
    assert.equal(await pq.verify(sig.publicKey, bytes, signature), true);
  }
});

test('all key formats roundtrip explicitly, keeping usages distinct', async () => {
  const imports = [pq.importEncryptionPublicKey, pq.importEncryptionPrivateKey, pq.importSigningPublicKey, pq.importSigningPrivateKey];
  const originals = [enc.publicKey, enc.privateKey, sig.publicKey, sig.privateKey];
  const lengths = [1578, 74, 2602, 42];
  for (let i = 0; i < originals.length; i++) {
    const bytes = await originals[i].export();
    assert.equal(bytes.length, lengths[i]);
    const imported = await imports[i](bytes);
    try {
      assert.deepEqual(await imported.export(), bytes);
      if (i === 1) {
        const ciphertext = await pq.encrypt(enc.publicKey, message);
        assert.deepEqual(await pq.decrypt(imported, ciphertext), message);
      }
      if (i === 3) assert.equal(await pq.verify(sig.publicKey, message, await pq.sign(imported, message)), true);
    } finally { if (imported.destroy) await imported.destroy(); bytes.fill(0); }
  }
  await assert.rejects(pq.importSigningPublicKey(await enc.publicKey.export()));
  assert.throws(() => pq.encrypt(sig.publicKey, message));
  assert.throws(() => pq.sign(enc.privateKey, message));
  for (const ctor of [pq.EncryptionPrivateKey, pq.SigningPrivateKey, pq.EncryptionPublicKey, pq.SigningPublicKey]) assert.throws(() => new ctor());
});

test('malformed envelopes and key formats reject lengths, versions and trailing bytes', async () => {
  const encrypted = await pq.encrypt(enc.publicKey, message);
  for (const bytes of [Buffer.alloc(0), encrypted.subarray(0, -1), Buffer.concat([encrypted, Buffer.of(0)])]) {
    await assert.rejects(pq.decrypt(enc.privateKey, bytes));
  }
  const version = Buffer.from(encrypted); version[4] = 99;
  await rejectsCode(pq.decrypt(enc.privateKey, version), 'ERR_UNSUPPORTED_VERSION');
  const excessive = Buffer.from(encrypted); excessive.writeUInt32LE(0xffffffff, 6);
  await rejectsCode(pq.decrypt(enc.privateKey, excessive), 'ERR_INVALID_FORMAT');
  const key = await enc.publicKey.export();
  for (const bytes of [key.subarray(0, -1), Buffer.concat([key, Buffer.of(0)]), Buffer.alloc(0)]) await assert.rejects(pq.importEncryptionPublicKey(bytes));
});

test('input copies are taken before workers can observe later JS mutation', async () => {
  const input = Buffer.from(message), associated = Buffer.from(aad), domain = Buffer.from(context);
  const encrypting = pq.encrypt(enc.publicKey, input, { aad: associated });
  const signing = pq.sign(sig.privateKey, input, { context: domain });
  input.fill(0); associated.fill(0); domain.fill(0);
  assert.deepEqual(await pq.decrypt(enc.privateKey, await encrypting, { aad }), message);
  assert.equal(await pq.verify(sig.publicKey, message, await signing, { context }), true);
  const secret = await sig.privateKey.export();
  const importing = pq.importSigningPrivateKey(secret); secret.fill(0);
  const imported = await importing;
  try { assert.equal(await pq.verify(sig.publicKey, message, await pq.sign(imported, message)), true); }
  finally { await imported.destroy(); }
});

test('rejects non-byte, shared and detached inputs', async () => {
  const shared = new Uint8Array(new SharedArrayBuffer(8));
  const detached = new Uint8Array(8); structuredClone(detached.buffer, { transfer: [detached.buffer] });
  for (const bytes of ['text', [1, 2], {}, new Uint16Array(3), new ArrayBuffer(8), shared, detached, null]) {
    await rejectsCode(pq.encrypt(enc.publicKey, bytes), 'ERR_INVALID_ARGUMENT');
    await rejectsCode(pq.sign(sig.privateKey, bytes), 'ERR_INVALID_ARGUMENT');
  }
  await rejectsCode(pq.encrypt(enc.publicKey, message, { aad: 'text' }), 'ERR_INVALID_ARGUMENT');
  await rejectsCode(pq.sign(sig.privateKey, message, { context: shared }), 'ERR_INVALID_ARGUMENT');
});

test('getters detaching an input cannot invalidate a previously captured native pointer', async () => {
  const bytes = new Uint8Array([1, 2, 3]);
  const options = { get aad() { structuredClone(bytes.buffer, { transfer: [bytes.buffer] }); return new Uint8Array(0); } };
  await rejectsCode(pq.encrypt(enc.publicKey, bytes, options), 'ERR_INVALID_ARGUMENT');
});

test('limits accept the boundary and reject excess before queuing expensive work', async () => {
  const maximum = Buffer.alloc(pq.MAX_MESSAGE_LEN, 0xa5);
  const encrypted = await pq.encrypt(enc.publicKey, maximum);
  assert.equal(encrypted.length, pq.MAX_ENVELOPE_LEN);
  assert.deepEqual(await pq.decrypt(enc.privateKey, encrypted), maximum);
  const signature = await pq.sign(sig.privateKey, maximum, { context: Buffer.alloc(255) });
  assert.equal(await pq.verify(sig.publicKey, maximum, signature, { context: Buffer.alloc(255) }), true);
  const excessive = Buffer.alloc(pq.MAX_MESSAGE_LEN + 1);
  await rejectsCode(pq.encrypt(enc.publicKey, excessive), 'ERR_MESSAGE_TOO_LARGE');
  await rejectsCode(pq.sign(sig.privateKey, excessive), 'ERR_MESSAGE_TOO_LARGE');
  await rejectsCode(pq.encrypt(enc.publicKey, message, { aad: excessive }), 'ERR_MESSAGE_TOO_LARGE');
  await rejectsCode(pq.sign(sig.privateKey, message, { context: Buffer.alloc(256) }), 'ERR_CONTEXT_TOO_LONG');
});

test('destroy revokes immediately, is idempotent and rejects subsequent accesses', async () => {
  const pair = await pq.generateSigningKeyPair();
  assert.equal(pair.privateKey.destroyed, false);
  const pending = Array.from({ length: 12 }, () => pq.sign(pair.privateKey, message));
  const destruction = pair.privateKey.destroy();
  assert.equal(pair.privateKey.destroyed, true);
  const results = await Promise.allSettled(pending);
  for (const result of results) {
    if (result.status === 'fulfilled') assert.equal(await pq.verify(pair.publicKey, message, result.value), true);
    else assert.equal(result.reason.code, 'ERR_KEY_DESTROYED');
  }
  await destruction;
  await rejectsCode(pq.sign(pair.privateKey, message), 'ERR_KEY_DESTROYED');
  await rejectsCode(pair.privateKey.export(), 'ERR_KEY_DESTROYED');
  await pair.privateKey.destroy();
});

test('concurrent operations and workers keep keys and Node environments isolated', async () => {
  await Promise.all(Array.from({ length: 16 }, async (_, i) => {
    const bytes = Buffer.from(`message ${i}`);
    const [ciphertext, signature] = await Promise.all([pq.encrypt(enc.publicKey, bytes), pq.sign(sig.privateKey, bytes)]);
    assert.deepEqual(await pq.decrypt(enc.privateKey, ciphertext), bytes);
    assert.equal(await pq.verify(sig.publicKey, bytes, signature), true);
  }));
  const path = require.resolve('../index.cjs');
  const worker = new Worker(`
    const { parentPort, workerData } = require('node:worker_threads');
    const pq = require(workerData);
    (async () => { const keys = await pq.generateSigningKeyPair();
      const message = Buffer.from('worker');
      const ok = await pq.verify(keys.publicKey, message, await pq.sign(keys.privateKey, message));
      await keys.privateKey.destroy(); parentPort.postMessage(ok); })();
  `, { eval: true, workerData: path });
  const result = await new Promise((resolve, reject) => { worker.once('message', resolve); worker.once('error', reject); });
  assert.equal(result, true);
  await worker.terminate();
});

test('cryptographic work yields to the event loop', async () => {
  const input = Buffer.alloc(pq.MAX_MESSAGE_LEN);
  const pending = pq.sign(sig.privateKey, input);
  let completed = false;
  pending.then(() => { completed = true; });
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(completed, false);
  await pending;
});
