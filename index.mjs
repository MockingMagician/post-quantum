import binding from './index.cjs';
export const {
  EncryptionPublicKey, EncryptionPrivateKey, SigningPublicKey, SigningPrivateKey,
  generateEncryptionKeyPair, generateSigningKeyPair, encrypt, decrypt, sign, verify,
  importEncryptionPublicKey, importEncryptionPrivateKey, importSigningPublicKey, importSigningPrivateKey,
  MAX_MESSAGE_LEN, MAX_AAD_LEN, MAX_CONTEXT_LEN, MAX_ENVELOPE_LEN,
} = binding;
export default binding;
