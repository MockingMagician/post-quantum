//! Versioned post-quantum encryption and signatures. See `docs/FORMAT.md` for the
//! exact wire protocol and `docs/SECURITY.md` for the security model and limitations.
#![forbid(unsafe_code)]

mod arithmetic;
mod hash;
mod ml_dsa;
mod ml_kem;
mod symmetric;
use post_quantum_platform::Zeroizing;

pub const MAX_MESSAGE_LEN: usize = 16 * 1024 * 1024;
pub const MAX_AAD_LEN: usize = MAX_MESSAGE_LEN;
pub const MAX_CONTEXT_LEN: usize = 255;
pub const HEADER_LEN: usize = 10;
pub const KEM_CIPHERTEXT_LEN: usize = 1568;
pub const SIGNATURE_LEN: usize = 4627;
pub const ENVELOPE_OVERHEAD: usize = HEADER_LEN + KEM_CIPHERTEXT_LEN + 12 + 16;
pub const MAX_ENVELOPE_LEN: usize = MAX_MESSAGE_LEN + ENVELOPE_OVERHEAD;
const MAGIC: &[u8; 4] = b"PQRS";
const VERSION: u8 = 1;
const ENC_PUBLIC: u8 = 1;
const ENC_PRIVATE: u8 = 2;
const SIG_PUBLIC: u8 = 3;
const SIG_PRIVATE: u8 = 4;
const ENCRYPTED: u8 = 16;
const SIGNED: u8 = 32;
const KDF_SALT: &[u8] = b"post-quantum/encryption/v1";
const SIGNATURE_DOMAIN: &[u8] = b"post-quantum/signature/v1";
const PREFIX_LEN: usize = HEADER_LEN + KEM_CIPHERTEXT_LEN + 12;

/// Errors contain no secret bytes and are stable across the native boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    InvalidFormat,
    InvalidKey,
    UnsupportedVersion,
    MessageTooLarge,
    ContextTooLong,
    AuthenticationFailed,
    RandomnessFailed,
    Internal,
}

impl Error {
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidFormat => "ERR_INVALID_FORMAT",
            Self::InvalidKey => "ERR_INVALID_KEY",
            Self::UnsupportedVersion => "ERR_UNSUPPORTED_VERSION",
            Self::MessageTooLarge => "ERR_MESSAGE_TOO_LARGE",
            Self::ContextTooLong => "ERR_CONTEXT_TOO_LONG",
            Self::AuthenticationFailed => "ERR_AUTHENTICATION_FAILED",
            Self::RandomnessFailed => "ERR_RANDOMNESS_FAILED",
            Self::Internal => "ERR_INTERNAL",
        }
    }
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.code())
    }
}
impl std::error::Error for Error {}
pub type Result<T> = core::result::Result<T, Error>;

#[derive(Clone)]
pub struct EncryptionPublicKey(ml_kem::PublicKey);
/// Owned secret material is erased by the local platform guard on drop.
pub struct EncryptionPrivateKey {
    inner: ml_kem::PrivateKey,
    seed: Zeroizing<[u8; 64]>,
}
#[derive(Clone)]
pub struct SigningPublicKey(ml_dsa::PublicKey);
/// Owned secret material is erased by the local platform guard on drop.
pub struct SigningPrivateKey {
    inner: ml_dsa::PrivateKey,
    seed: Zeroizing<[u8; 32]>,
}

fn header(kind: u8, payload_len: usize) -> [u8; HEADER_LEN] {
    let mut result = [0; HEADER_LEN];
    result[..4].copy_from_slice(MAGIC);
    result[4] = VERSION;
    result[5] = kind;
    result[6..].copy_from_slice(&(payload_len as u32).to_le_bytes());
    result
}

fn encode(kind: u8, payload: &[u8]) -> Vec<u8> {
    let mut result = Vec::with_capacity(HEADER_LEN + payload.len());
    result.extend_from_slice(&header(kind, payload.len()));
    result.extend_from_slice(payload);
    result
}

/// Parse without allocating. Every caller also checks its type-specific size.
fn decode(bytes: &[u8], kind: u8) -> Result<&[u8]> {
    if bytes.len() < HEADER_LEN || &bytes[..4] != MAGIC {
        return Err(Error::InvalidFormat);
    }
    if bytes[4] != VERSION {
        return Err(Error::UnsupportedVersion);
    }
    if bytes[5] != kind {
        return Err(Error::InvalidFormat);
    }
    let len =
        u32::from_le_bytes(bytes[6..10].try_into().map_err(|_| Error::InvalidFormat)?) as usize;
    if bytes.len() - HEADER_LEN != len {
        return Err(Error::InvalidFormat);
    }
    Ok(&bytes[HEADER_LEN..])
}

impl EncryptionPublicKey {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let payload = decode(bytes, ENC_PUBLIC)?;
        ml_kem::PublicKey::from_bytes(payload)
            .map(Self)
            .map_err(|_| Error::InvalidKey)
    }
    pub fn to_bytes(&self) -> Vec<u8> {
        encode(ENC_PUBLIC, self.0.as_bytes())
    }
}
impl EncryptionPrivateKey {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let payload = decode(bytes, ENC_PRIVATE)?;
        let seed = Zeroizing::new(<[u8; 64]>::try_from(payload).map_err(|_| Error::InvalidKey)?);
        Ok(Self {
            inner: ml_kem::PrivateKey::from_seed(&seed),
            seed,
        })
    }
    /// Explicit secret export: caller must protect and erase these bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        encode(ENC_PRIVATE, &self.seed[..])
    }
    pub fn public_key(&self) -> EncryptionPublicKey {
        EncryptionPublicKey(self.inner.public_key())
    }
}
impl SigningPublicKey {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let payload = decode(bytes, SIG_PUBLIC)?;
        ml_dsa::PublicKey::from_bytes(payload)
            .map(Self)
            .map_err(|_| Error::InvalidKey)
    }
    pub fn to_bytes(&self) -> Vec<u8> {
        encode(SIG_PUBLIC, self.0.as_bytes())
    }
}
impl SigningPrivateKey {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let payload = decode(bytes, SIG_PRIVATE)?;
        let seed = Zeroizing::new(<[u8; 32]>::try_from(payload).map_err(|_| Error::InvalidKey)?);
        Ok(Self {
            inner: ml_dsa::PrivateKey::from_seed(&seed),
            seed,
        })
    }
    /// Explicit secret export: caller must protect and erase these bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        encode(SIG_PRIVATE, &self.seed[..])
    }
    pub fn public_key(&self) -> SigningPublicKey {
        SigningPublicKey(self.inner.public_key())
    }
}

/// Private injection point for tests. Production always uses the OS source.
trait TryRandom {
    fn try_fill_bytes(&mut self, bytes: &mut [u8]) -> core::result::Result<(), ()>;
}
struct OsRandom;
impl TryRandom for OsRandom {
    fn try_fill_bytes(&mut self, bytes: &mut [u8]) -> core::result::Result<(), ()> {
        post_quantum_platform::fill_random(bytes)
    }
}
pub fn generate_encryption_key_pair() -> Result<(EncryptionPublicKey, EncryptionPrivateKey)> {
    generate_encryption_with_rng(&mut OsRandom)
}
fn generate_encryption_with_rng<R: TryRandom>(
    rng: &mut R,
) -> Result<(EncryptionPublicKey, EncryptionPrivateKey)> {
    let mut seed = Zeroizing::new([0; 64]);
    rng.try_fill_bytes(&mut seed[..])
        .map_err(|_| Error::RandomnessFailed)?;
    let private = EncryptionPrivateKey {
        inner: ml_kem::PrivateKey::from_seed(&seed),
        seed,
    };
    Ok((private.public_key(), private))
}
pub fn generate_signing_key_pair() -> Result<(SigningPublicKey, SigningPrivateKey)> {
    generate_signing_with_rng(&mut OsRandom)
}
fn generate_signing_with_rng<R: TryRandom>(
    rng: &mut R,
) -> Result<(SigningPublicKey, SigningPrivateKey)> {
    let mut seed = Zeroizing::new([0; 32]);
    rng.try_fill_bytes(&mut seed[..])
        .map_err(|_| Error::RandomnessFailed)?;
    let private = SigningPrivateKey {
        inner: ml_dsa::PrivateKey::from_seed(&seed),
        seed,
    };
    Ok((private.public_key(), private))
}

fn check_message(bytes: &[u8]) -> Result<()> {
    if bytes.len() > MAX_MESSAGE_LEN {
        Err(Error::MessageTooLarge)
    } else {
        Ok(())
    }
}
fn check_context(context: &[u8]) -> Result<()> {
    if context.len() > MAX_CONTEXT_LEN {
        Err(Error::ContextTooLong)
    } else {
        Ok(())
    }
}

fn derive_key(
    shared: &[u8],
    public: &EncryptionPublicKey,
    prefix: &[u8],
) -> Result<Zeroizing<[u8; 32]>> {
    let mut output = Zeroizing::new([0; 32]);
    symmetric::hkdf_sha512(
        shared,
        KDF_SALT,
        &[
            &prefix[..HEADER_LEN],
            public.0.as_bytes(),
            &prefix[HEADER_LEN..],
        ],
        &mut output[..],
    )
    .map_err(|_| Error::Internal)?;
    Ok(output)
}
/// AAD is authenticated but not embedded; a new encapsulation and nonce are used.
pub fn encrypt(public: &EncryptionPublicKey, message: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    encrypt_with_rng(public, message, aad, &mut OsRandom)
}
fn encrypt_with_rng<R: TryRandom>(
    public: &EncryptionPublicKey,
    message: &[u8],
    aad: &[u8],
    rng: &mut R,
) -> Result<Vec<u8>> {
    check_message(message)?;
    check_message(aad)?;
    let mut randomness = Zeroizing::new([0; 32]);
    let mut nonce = [0; 12];
    rng.try_fill_bytes(&mut randomness[..])
        .map_err(|_| Error::RandomnessFailed)?;
    rng.try_fill_bytes(&mut nonce)
        .map_err(|_| Error::RandomnessFailed)?;
    let (ciphertext, shared) = public.0.encapsulate(&randomness);
    let mut prefix = Vec::with_capacity(PREFIX_LEN);
    prefix.extend_from_slice(&header(
        ENCRYPTED,
        message.len() + ENVELOPE_OVERHEAD - HEADER_LEN,
    ));
    prefix.extend_from_slice(&ciphertext);
    prefix.extend_from_slice(&nonce);
    let key = derive_key(&shared[..], public, &prefix)?;
    let aad_len = (aad.len() as u64).to_le_bytes();
    let encrypted = symmetric::seal(&key, &nonce, &[&prefix, &aad_len, aad], message);
    prefix.reserve(encrypted.len());
    prefix.extend_from_slice(&encrypted);
    Ok(prefix)
}
pub fn decrypt(private: &EncryptionPrivateKey, envelope: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    check_message(aad)?;
    if envelope.len() > MAX_ENVELOPE_LEN {
        return Err(Error::MessageTooLarge);
    }
    let payload = decode(envelope, ENCRYPTED)?;
    if payload.len() < ENVELOPE_OVERHEAD - HEADER_LEN {
        return Err(Error::InvalidFormat);
    }
    let shared = private
        .inner
        .decapsulate(&payload[..KEM_CIPHERTEXT_LEN])
        .map_err(|_| Error::InvalidFormat)?;
    let key = derive_key(&shared[..], &private.public_key(), &envelope[..PREFIX_LEN])?;
    let nonce = <&[u8; 12]>::try_from(&envelope[PREFIX_LEN - 12..PREFIX_LEN])
        .map_err(|_| Error::InvalidFormat)?;
    let aad_len = (aad.len() as u64).to_le_bytes();
    symmetric::open(
        &key,
        nonce,
        &[&envelope[..PREFIX_LEN], &aad_len, aad],
        &envelope[PREFIX_LEN..],
    )
    .map_err(|_| Error::AuthenticationFailed)
}

fn signing_transcript(message: &[u8], context: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut transcript = Zeroizing::new(Vec::with_capacity(
        HEADER_LEN + 2 + context.len() + message.len(),
    ));
    transcript.extend_from_slice(&header(SIGNED, SIGNATURE_LEN));
    transcript.extend_from_slice(&(context.len() as u16).to_le_bytes());
    transcript.extend_from_slice(context);
    transcript.extend_from_slice(message);
    transcript
}

/// Randomized pure ML-DSA, with a fixed FIPS context plus a framed application
/// context in the signed message. Context bytes are not embedded in the output.
pub fn sign(private: &SigningPrivateKey, message: &[u8], context: &[u8]) -> Result<Vec<u8>> {
    sign_with_rng(private, message, context, &mut OsRandom)
}
fn sign_with_rng<R: TryRandom>(
    private: &SigningPrivateKey,
    message: &[u8],
    context: &[u8],
    rng: &mut R,
) -> Result<Vec<u8>> {
    check_message(message)?;
    check_context(context)?;
    let mut randomness = Zeroizing::new([0; 32]);
    rng.try_fill_bytes(&mut randomness[..])
        .map_err(|_| Error::RandomnessFailed)?;
    let transcript = signing_transcript(message, context);
    let signature = private
        .inner
        .sign(&transcript, SIGNATURE_DOMAIN, &randomness)
        .map_err(|_| Error::Internal)?;
    Ok(encode(SIGNED, &signature))
}

/// Invalid or malformed signatures return false. Invalid API inputs (oversized
/// messages or context) return errors, as with sign().
pub fn verify(
    public: &SigningPublicKey,
    message: &[u8],
    signature: &[u8],
    context: &[u8],
) -> Result<bool> {
    check_message(message)?;
    check_context(context)?;
    if signature.len() != HEADER_LEN + SIGNATURE_LEN {
        return Ok(false);
    }
    let Ok(payload) = decode(signature, SIGNED) else {
        return Ok(false);
    };
    let transcript = signing_transcript(message, context);
    Ok(public.0.verify(&transcript, SIGNATURE_DOMAIN, payload))
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod primitive_vectors;
#[cfg(test)]
mod symmetric_reference_tests;
#[cfg(test)]
mod validation_tests;
#[cfg(test)]
mod test_support {
    use super::{ml_dsa, ml_kem};
    pub fn kem_keygen(seed: &[u8; 64]) -> (Vec<u8>, Vec<u8>) {
        let private = ml_kem::PrivateKey::from_seed(seed);
        (
            private.public_key().as_bytes().to_vec(),
            private.expanded_bytes(),
        )
    }
    pub fn kem_encapsulate(ek: &[u8], m: &[u8; 32]) -> Result<(Vec<u8>, [u8; 32]), ()> {
        let (ct, ss) = ml_kem::PublicKey::from_bytes(ek)?.encapsulate(m);
        Ok((ct, *ss))
    }
    pub fn kem_decapsulate(dk: &[u8], ct: &[u8]) -> Result<[u8; 32], ()> {
        Ok(*ml_kem::PrivateKey::from_expanded(dk)?.decapsulate(ct)?)
    }
    pub fn kem_check_public(ek: &[u8]) -> bool {
        ml_kem::PublicKey::from_bytes(ek).is_ok()
    }
    pub fn kem_check_private(dk: &[u8]) -> bool {
        ml_kem::PrivateKey::from_expanded(dk).is_ok()
    }
    pub fn dsa_keygen(seed: &[u8; 32]) -> (Vec<u8>, Vec<u8>) {
        let private = ml_dsa::PrivateKey::from_seed(seed);
        (
            private.public_key().as_bytes().to_vec(),
            private.expanded_bytes(),
        )
    }
    pub fn dsa_sign_internal(sk: &[u8], mp: &[u8], rnd: &[u8; 32]) -> Result<Vec<u8>, ()> {
        ml_dsa::PrivateKey::from_expanded(sk)?.sign_internal(mp, rnd)
    }
    pub fn dsa_verify_internal(pk: &[u8], mp: &[u8], sig: &[u8]) -> bool {
        ml_dsa::PublicKey::from_bytes(pk).is_ok_and(|key| key.verify_internal(mp, sig))
    }
}

#[cfg(test)]
#[path = "../tests/support/mod.rs"]
mod validation_support;
