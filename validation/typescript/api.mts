import {
  generateEncryptionKeyPair, generateSigningKeyPair, encrypt, decrypt, sign, verify,
  importSigningPrivateKey, EncryptionPublicKey, type CryptoErrorCode,
} from 'post-quantum';

async function useApi() {
  const recipient = await generateEncryptionKeyPair();
  const author = await generateSigningKeyPair();
  const bytes = Buffer.from('message');
  const encrypted: Buffer = await encrypt(recipient.publicKey, bytes, { aad: new Uint8Array() });
  const decrypted: Buffer = await decrypt(recipient.privateKey, encrypted);
  const signature: Buffer = await sign(author.privateKey, decrypted, { context: bytes });
  const valid: boolean = await verify(author.publicKey, decrypted, signature);
  const imported = await importSigningPrivateKey(await author.privateKey.export());
  const revoked: boolean = imported.destroyed;
  await imported.destroy();
  // @ts-expect-error distinct public key usage is enforced by nominal declarations
  await encrypt(author.publicKey, bytes);
  // @ts-expect-error private encryption key is not a signing key
  await sign(recipient.privateKey, bytes);
  // @ts-expect-error implicit text conversion is not supported
  await encrypt(recipient.publicKey, 'text');
  // @ts-expect-error opaque classes are not constructible
  new EncryptionPublicKey();
  // @ts-expect-error destroyed is read-only
  imported.destroyed = true;
  const code: CryptoErrorCode = 'ERR_KEY_DESTROYED';
  return { valid, revoked, code };
}
void useApi;
