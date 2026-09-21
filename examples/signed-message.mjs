// Application-level signed payload, encrypted to one authenticated recipient.
// Both public keys must come from the application's trusted identity mechanism.
import { pathToFileURL } from 'node:url';
import {
  generateEncryptionKeyPair, generateSigningKeyPair,
  encrypt, decrypt, sign, verify, MAX_MESSAGE_LEN,
} from '../index.mjs';

const domain = Buffer.from('example/signed-message/v1');
const signatureSize = 4637; // Version 1 signature envelope; see FORMAT.md.
const framingSize = 4 + signatureSize;
const recipientKeySize = 1578;

export async function sealSigned(recipientPublicKey, authorPrivateKey, message, metadata) {
  if (!(message instanceof Uint8Array) || !(metadata instanceof Uint8Array)) throw new Error('Type invalide');
  if (message.byteLength > MAX_MESSAGE_LEN - framingSize || message.byteLength + metadata.byteLength + recipientKeySize + 4 > MAX_MESSAGE_LEN) throw new Error('Message ou métadonnées trop longs');
  // Own the bytes across awaits, including metadata. It may contain an app
  // message ID/expiry; the caller still enforces replay policy on receipt.
  let owned, aad, transcript, frame;
  try {
    owned = Buffer.from(message);
    aad = Buffer.from(metadata);
    const recipient = await recipientPublicKey.export();
    if (recipient.length !== recipientKeySize) throw new Error('Clé destinataire invalide');
    transcript = Buffer.concat([recipient, lengthPrefix(aad), aad, owned]);
    const signature = await sign(authorPrivateKey, transcript, { context: domain });
    frame = Buffer.concat([lengthPrefix(signature), signature, owned]);
    return await encrypt(recipientPublicKey, frame, { aad });
  } finally { owned?.fill(0); aad?.fill(0); transcript?.fill(0); frame?.fill(0); }
}

export async function openSigned(recipientPrivateKey, recipientPublicKey, trustedAuthorPublicKey, encrypted, metadata) {
  if (!(metadata instanceof Uint8Array) || metadata.byteLength > MAX_MESSAGE_LEN - recipientKeySize - 4) throw new Error('Métadonnées invalides');
  const aad = Buffer.from(metadata);
  const frame = await decrypt(recipientPrivateKey, encrypted, { aad });
  let transcript;
  try {
    if (frame.length < framingSize || frame.readUInt32LE(0) !== signatureSize) throw new Error('Cadre signé invalide');
    const signature = frame.subarray(4, framingSize);
    const message = frame.subarray(framingSize);
    const recipient = await recipientPublicKey.export();
    if (recipient.length !== recipientKeySize || recipient.length + 4 + aad.length + message.length > MAX_MESSAGE_LEN) throw new Error('Cadre signé trop long');
    transcript = Buffer.concat([recipient, lengthPrefix(aad), aad, message]);
    if (!await verify(trustedAuthorPublicKey, transcript, signature, { context: domain })) throw new Error('Signature invalide');
    return Buffer.from(message); // No plaintext escapes before signature verification.
  } finally { frame.fill(0); aad.fill(0); transcript?.fill(0); }
}

function lengthPrefix(bytes) {
  const prefix = Buffer.alloc(4); prefix.writeUInt32LE(bytes.length); return prefix;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const recipient = await generateEncryptionKeyPair();
  const author = await generateSigningKeyPair();
  try {
    const metadata = Buffer.from('message-id:42');
    const encrypted = await sealSigned(recipient.publicKey, author.privateKey, Buffer.from('Bonjour'), metadata);
    const message = await openSigned(recipient.privateKey, recipient.publicKey, author.publicKey, encrypted, metadata);
    console.log(message.toString('utf8'));
  } finally { await Promise.all([recipient.privateKey.destroy(), author.privateKey.destroy()]); }
}
