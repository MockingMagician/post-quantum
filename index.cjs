'use strict';
const { existsSync } = require('node:fs');
const { join } = require('node:path');
const target = require('./lib/platform.cjs')();
const local = join(__dirname, 'native', `post_quantum.${target}.node`);
if (existsSync(local)) {
  module.exports = require(local);
} else {
  try {
    module.exports = require(`post-quantum-${target}`);
  } catch (cause) {
    const error = new Error(
      `Unable to load post-quantum for ${target}. Install the matching platform package at the same version, or run npm run build in a source checkout.`,
      { cause },
    );
    error.code = 'ERR_NATIVE_BINDING_UNAVAILABLE';
    throw error;
  }
}

// A bootstrap failure must never look like a successfully loaded, partial API.
const requiredFunctions = [
  'EncryptionPublicKey', 'EncryptionPrivateKey', 'SigningPublicKey', 'SigningPrivateKey',
  'generateEncryptionKeyPair', 'generateSigningKeyPair',
  'importEncryptionPublicKey', 'importEncryptionPrivateKey', 'importSigningPublicKey', 'importSigningPrivateKey',
  'encrypt', 'decrypt', 'sign', 'verify',
];
const requiredConstants = ['MAX_MESSAGE_LEN', 'MAX_AAD_LEN', 'MAX_CONTEXT_LEN', 'MAX_ENVELOPE_LEN'];
const allowedExports = new Set([...requiredFunctions, ...requiredConstants]);
if (requiredFunctions.some(name => typeof module.exports[name] !== 'function') ||
    requiredConstants.some(name => !Number.isSafeInteger(module.exports[name])) ||
    Reflect.ownKeys(module.exports).some(name => !allowedExports.has(name))) {
  const error = new Error('The native post-quantum module does not expose exactly the production Node-API interface.');
  error.code = 'ERR_NATIVE_BINDING_UNAVAILABLE';
  throw error;
}
