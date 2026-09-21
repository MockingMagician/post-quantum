'use strict';
const assert = require('node:assert/strict');
const { createRequire } = require('node:module');
const { join } = require('node:path');

(async () => {
  const directory = process.argv[2];
  const requireInstalled = createRequire(join(directory, 'package.json'));
  const api = requireInstalled('post-quantum');
  const expectedExports = [
    'EncryptionPublicKey', 'EncryptionPrivateKey', 'SigningPublicKey', 'SigningPrivateKey',
    'generateEncryptionKeyPair', 'generateSigningKeyPair',
    'importEncryptionPublicKey', 'importEncryptionPrivateKey', 'importSigningPublicKey', 'importSigningPrivateKey',
    'encrypt', 'decrypt', 'sign', 'verify',
    'MAX_MESSAGE_LEN', 'MAX_AAD_LEN', 'MAX_CONTEXT_LEN', 'MAX_ENVELOPE_LEN',
  ];
  assert.deepEqual(Object.getOwnPropertyNames(api).sort(), expectedExports.sort(), 'Archive must expose exactly the production API, including non-enumerable exports');
  assert.equal(Object.getOwnPropertySymbols(api).length, 0, 'Archive must not expose undocumented symbol exports');
  // The ESM entry is loaded from the installed archive, not the checkout.
  const esm = await import('post-quantum');
  for (const [key, value] of Object.entries(api)) assert.equal(esm[key], value, `ESM/CJS export mismatch: ${key}`);
  const message = Buffer.from('Archive installation: ML-KEM-1024 + ML-DSA-87');
  const aad = Buffer.from('archive-aad');
  const context = Buffer.from('archive-signature');
  const encryption = await api.generateEncryptionKeyPair();
  const signing = await api.generateSigningKeyPair();
  const envelope = await api.encrypt(encryption.publicKey, message, { aad });
  assert.deepEqual(await api.decrypt(encryption.privateKey, envelope, { aad }), message);
  const signature = await api.sign(signing.privateKey, message, { context });
  assert.equal(await api.verify(signing.publicKey, message, signature, { context }), true);
  assert.equal(await api.verify(signing.publicKey, Buffer.from('wrong message'), signature, { context }), false);
  const corrupt = Buffer.from(envelope);
  corrupt[corrupt.length - 1] ^= 1;
  await assert.rejects(api.decrypt(encryption.privateKey, corrupt, { aad }));
  for (const [key, importer] of [
    [encryption.publicKey, api.importEncryptionPublicKey], [encryption.privateKey, api.importEncryptionPrivateKey],
    [signing.publicKey, api.importSigningPublicKey], [signing.privateKey, api.importSigningPrivateKey],
  ]) {
    const bytes = await key.export();
    const imported = await importer(bytes);
    assert.deepEqual(await imported.export(), bytes);
    if (imported.destroy) await imported.destroy();
    bytes.fill(0);
  }
  await encryption.privateKey.destroy();
  await signing.privateKey.destroy();
  assert.equal(encryption.privateKey.destroyed, true);
  assert.equal(signing.privateKey.destroyed, true);
  console.log(JSON.stringify({ passed: true, node: process.version, tests: ['CJS load', 'production export allowlist', 'ESM load', 'encryption round trip', 'signature verification', 'tamper rejection', 'key imports/exports', 'private key destruction'] }));
})().catch((error) => { console.error(error); process.exitCode = 1; });
