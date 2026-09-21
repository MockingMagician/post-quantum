'use strict';
const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const pq = require('../index.cjs');

let encryption, signing;
const message = Buffer.from('Native class and reentrancy regression');
before(async () => {
  [encryption, signing] = await Promise.all([
    pq.generateEncryptionKeyPair(), pq.generateSigningKeyPair(),
  ]);
});
after(async () => {
  await Promise.all([encryption.privateKey.destroy(), signing.privateKey.destroy()]);
});

test('prototype-only key objects cannot reach native key pointers', () => {
  for (const [Type, operation] of [
    [pq.EncryptionPublicKey, key => pq.encrypt(key, message)],
    [pq.EncryptionPrivateKey, key => pq.decrypt(key, Buffer.alloc(0))],
    [pq.SigningPublicKey, key => pq.verify(key, message, Buffer.alloc(0))],
    [pq.SigningPrivateKey, key => pq.sign(key, message)],
  ]) {
    const forged = Object.create(Type.prototype);
    assert.throws(() => operation(forged));
    assert.throws(() => forged.export());
  }
});

test('changing a real key prototype does not change its native type tag', () => {
  for (const [key, wrongPrototype, operation] of [
    [signing.publicKey, pq.EncryptionPublicKey.prototype, value => pq.encrypt(value, message)],
    [encryption.publicKey, pq.SigningPublicKey.prototype, value => pq.verify(value, message, Buffer.alloc(0))],
    [signing.privateKey, pq.EncryptionPrivateKey.prototype, value => pq.decrypt(value, Buffer.alloc(0))],
    [encryption.privateKey, pq.SigningPrivateKey.prototype, value => pq.sign(value, message)],
  ]) {
    const original = Object.getPrototypeOf(key);
    try {
      Object.setPrototypeOf(key, wrongPrototype);
      assert.throws(() => operation(key));
    } finally {
      Object.setPrototypeOf(key, original);
    }
  }
});

test('borrowed methods and accessors reject keys of another native class', async () => {
  for (const [Type, wrongKey] of [
    [pq.EncryptionPublicKey, signing.publicKey],
    [pq.SigningPublicKey, encryption.publicKey],
    [pq.EncryptionPrivateKey, signing.privateKey],
    [pq.SigningPrivateKey, encryption.privateKey],
  ]) {
    assert.throws(() => Type.prototype.export.call(wrongKey));
    if (Type.prototype.destroy) {
      assert.throws(() => Type.prototype.destroy.call(wrongKey));
      const getter = Object.getOwnPropertyDescriptor(Type.prototype, 'destroyed').get;
      assert.throws(() => getter.call(wrongKey));
    }
  }
  // Wrong receiver calls must not revoke the actual keys as a side effect.
  assert.equal(signing.privateKey.destroyed, false);
  assert.equal(encryption.privateKey.destroyed, false);
  const signature = await pq.sign(signing.privateKey, message);
  assert.equal(await pq.verify(signing.publicKey, message, signature), true);
});

test('an options getter can revoke the key before a worker starts', async () => {
  const signingPair = await pq.generateSigningKeyPair();
  const encryptionPair = await pq.generateEncryptionKeyPair();
  const envelope = await pq.encrypt(encryptionPair.publicKey, message);
  let signingDestruction, encryptionDestruction;
  try {
    const signature = pq.sign(signingPair.privateKey, message, {
      get context() {
        signingDestruction = signingPair.privateKey.destroy();
        return new Uint8Array(0);
      },
    });
    const plaintext = pq.decrypt(encryptionPair.privateKey, envelope, {
      get aad() {
        encryptionDestruction = encryptionPair.privateKey.destroy();
        return new Uint8Array(0);
      },
    });
    assert.equal(signingPair.privateKey.destroyed, true);
    assert.equal(encryptionPair.privateKey.destroyed, true);
    await Promise.all([
      assert.rejects(signature, { code: 'ERR_KEY_DESTROYED' }),
      assert.rejects(plaintext, { code: 'ERR_KEY_DESTROYED' }),
      signingDestruction,
      encryptionDestruction,
    ]);
  } finally {
    await Promise.all([signingPair.privateKey.destroy(), encryptionPair.privateKey.destroy()]);
  }
});

test('exceptions thrown by options getters preserve the exception and key validity', async () => {
  const marker = new Error('Getter failure sentinel');
  assert.throws(() => pq.sign(signing.privateKey, message, {
    get context() { throw marker; },
  }), error => error === marker);
  const signature = await pq.sign(signing.privateKey, message);
  assert.equal(await pq.verify(signing.publicKey, message, signature), true);
});
