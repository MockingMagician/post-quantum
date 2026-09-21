/// <reference types="node" />

/** ML-KEM-1024 public key. Create with generation or import functions. */
export class EncryptionPublicKey {
  private constructor();
  private readonly __encryptionPublicKey: never;
  export(): Promise<Buffer>;
}
/** Opaque Rust-owned private key; export deliberately releases secret bytes. */
export class EncryptionPrivateKey {
  private constructor();
  private readonly __encryptionPrivateKey: never;
  readonly destroyed: boolean;
  export(): Promise<Buffer>;
  /** Revokes immediately; resolves after ongoing access and erasure complete. */
  destroy(): Promise<void>;
}
/** ML-DSA-87 public key; identity/trust is the caller's responsibility. */
export class SigningPublicKey {
  private constructor();
  private readonly __signingPublicKey: never;
  export(): Promise<Buffer>;
}
export class SigningPrivateKey {
  private constructor();
  private readonly __signingPrivateKey: never;
  readonly destroyed: boolean;
  export(): Promise<Buffer>;
  destroy(): Promise<void>;
}
export interface EncryptionKeyPair {
  publicKey: EncryptionPublicKey;
  privateKey: EncryptionPrivateKey;
}
export interface SigningKeyPair {
  publicKey: SigningPublicKey;
  privateKey: SigningPrivateKey;
}
export interface EncryptionOptions {
  /** Authenticated but not encrypted or embedded. Both parties supply identical bytes. */
  aad?: Uint8Array;
}
export interface SignatureOptions {
  /** Application domain, at most 255 bytes; supply identical bytes to verify. */
  context?: Uint8Array;
}
export const MAX_MESSAGE_LEN: number;
export const MAX_AAD_LEN: number;
export const MAX_CONTEXT_LEN: number;
export const MAX_ENVELOPE_LEN: number;
export function generateEncryptionKeyPair(): Promise<EncryptionKeyPair>;
export function generateSigningKeyPair(): Promise<SigningKeyPair>;
export function importEncryptionPublicKey(bytes: Uint8Array): Promise<EncryptionPublicKey>;
export function importEncryptionPrivateKey(bytes: Uint8Array): Promise<EncryptionPrivateKey>;
export function importSigningPublicKey(bytes: Uint8Array): Promise<SigningPublicKey>;
export function importSigningPrivateKey(bytes: Uint8Array): Promise<SigningPrivateKey>;
export function encrypt(publicKey: EncryptionPublicKey, message: Uint8Array, options?: EncryptionOptions): Promise<Buffer>;
export function decrypt(privateKey: EncryptionPrivateKey, envelope: Uint8Array, options?: EncryptionOptions): Promise<Buffer>;
export function sign(privateKey: SigningPrivateKey, message: Uint8Array, options?: SignatureOptions): Promise<Buffer>;
/** Invalid, malformed or non-matching signatures return false; invalid arguments reject/throw. */
export function verify(publicKey: SigningPublicKey, message: Uint8Array, signature: Uint8Array, options?: SignatureOptions): Promise<boolean>;
export type CryptoErrorCode =
  | 'ERR_INVALID_ARGUMENT' | 'ERR_INVALID_FORMAT' | 'ERR_INVALID_KEY'
  | 'ERR_UNSUPPORTED_VERSION' | 'ERR_MESSAGE_TOO_LARGE' | 'ERR_CONTEXT_TOO_LONG'
  | 'ERR_AUTHENTICATION_FAILED' | 'ERR_RANDOMNESS_FAILED' | 'ERR_KEY_DESTROYED'
  | 'ERR_INTERNAL';
