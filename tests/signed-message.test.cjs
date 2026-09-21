const { test } = require('node:test');
const assert = require('node:assert/strict');
const pq = require('../index.cjs');

test('signed encryption example only returns an authenticated author message', async () => {
  const { sealSigned, openSigned } = await import('../examples/signed-message.mjs');
  const recipient = await pq.generateEncryptionKeyPair();
  const author = await pq.generateSigningKeyPair();
  const attacker = await pq.generateSigningKeyPair();
  const message = Buffer.from('contenu signé');
  const metadata = Buffer.from('app:message:42');
  try {
    const encrypted = await sealSigned(recipient.publicKey, author.privateKey, message, metadata);
    assert.deepEqual(await openSigned(recipient.privateKey, recipient.publicKey, author.publicKey, encrypted, metadata), message);
    await assert.rejects(openSigned(recipient.privateKey, recipient.publicKey, attacker.publicKey, encrypted, metadata), /Signature invalide/);
    await assert.rejects(openSigned(recipient.privateKey, recipient.publicKey, author.publicKey, encrypted, Buffer.from('wrong')), { code: 'ERR_AUTHENTICATION_FAILED' });
    const unsigned = await pq.encrypt(recipient.publicKey, message, { aad: metadata });
    await assert.rejects(openSigned(recipient.privateKey, recipient.publicKey, author.publicKey, unsigned, metadata), /Cadre signé invalide/);
    // Anyone can encrypt; an envelope with a fabricated inner signature must
    // still be rejected, even when its outer AEAD authentication is valid.
    const forged = Buffer.alloc(4 + 4637 + message.length);
    forged.writeUInt32LE(4637); message.copy(forged, 4 + 4637);
    const forgedEncrypted = await pq.encrypt(recipient.publicKey, forged, { aad: metadata });
    await assert.rejects(openSigned(recipient.privateKey, recipient.publicKey, author.publicKey, forgedEncrypted, metadata), /Signature invalide/);
  } finally { await Promise.all([recipient.privateKey.destroy(), author.privateKey.destroy(), attacker.privateKey.destroy()]); }
});
