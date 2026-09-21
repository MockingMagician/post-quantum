//! Rust-only Node-API 8 adapter. No third-party runtime or build dependencies.
//! Unsafe code is confined to checked Node/OS interfaces and their callbacks.
mod ffi;
mod runtime;

use ffi::*;
use post_quantum_core as core;
use post_quantum_platform::Zeroizing;
use runtime::*;
use std::{
    ffi::CStr,
    ptr::null_mut,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
};

struct Secret<T> {
    value: Mutex<Option<T>>,
    revoked: AtomicBool,
}
impl<T> Secret<T> {
    fn new(value: T) -> Arc<Self> {
        Arc::new(Self {
            value: Mutex::new(Some(value)),
            revoked: AtomicBool::new(false),
        })
    }
    fn with<R>(&self, f: impl FnOnce(&T) -> Result<R>) -> Result<R> {
        if self.revoked.load(Ordering::Acquire) {
            return Err(destroyed());
        }
        let guard = self.value.lock().map_err(|_| internal())?;
        if self.revoked.load(Ordering::Acquire) {
            return Err(destroyed());
        }
        f(guard.as_ref().ok_or_else(destroyed)?)
    }
    fn erase(&self) -> Result<Output> {
        self.value.lock().unwrap_or_else(|e| e.into_inner()).take();
        Ok(Output::Unit)
    }
}
fn destroyed() -> Failure {
    Failure::new("ERR_KEY_DESTROYED", "Private key has been destroyed")
}
#[derive(Clone)]
enum Key {
    EncryptionPublic(Arc<core::EncryptionPublicKey>),
    EncryptionPrivate(Arc<Secret<core::EncryptionPrivateKey>>),
    SigningPublic(Arc<core::SigningPublicKey>),
    SigningPrivate(Arc<Secret<core::SigningPrivateKey>>),
}
impl Key {
    fn kind(&self) -> usize {
        match self {
            Self::EncryptionPublic(_) => 0,
            Self::EncryptionPrivate(_) => 1,
            Self::SigningPublic(_) => 2,
            Self::SigningPrivate(_) => 3,
        }
    }
    fn export(&self) -> Result<Output> {
        match self {
            Self::EncryptionPublic(key) => Ok(bytes(key.to_bytes())),
            Self::SigningPublic(key) => Ok(bytes(key.to_bytes())),
            Self::EncryptionPrivate(key) => key.with(|key| Ok(bytes(key.to_bytes()))),
            Self::SigningPrivate(key) => key.with(|key| Ok(bytes(key.to_bytes()))),
        }
    }
    fn revoke(&self) -> Result<()> {
        match self {
            Self::EncryptionPrivate(key) => key.revoked.store(true, Ordering::Release),
            Self::SigningPrivate(key) => key.revoked.store(true, Ordering::Release),
            _ => return Err(invalid()),
        }
        Ok(())
    }
    fn erase(&self) -> Result<Output> {
        match self {
            Self::EncryptionPrivate(key) => key.erase(),
            Self::SigningPrivate(key) => key.erase(),
            _ => Err(invalid()),
        }
    }
    fn destroyed(&self) -> Result<bool> {
        match self {
            Self::EncryptionPrivate(key) => Ok(key.revoked.load(Ordering::Acquire)),
            Self::SigningPrivate(key) => Ok(key.revoked.load(Ordering::Acquire)),
            _ => Err(invalid()),
        }
    }
}
enum Output {
    Bytes(Zeroizing<Vec<u8>>),
    Bool(bool),
    Unit,
    Key(Key),
    Pair(Key, Key),
}
fn bytes(bytes: Vec<u8>) -> Output {
    Output::Bytes(Zeroizing::new(bytes))
}

unsafe extern "C" fn callback(env: Env, info: CallbackInfo) -> Value {
    boundary(env, || unsafe {
        let args = arguments(env, info)?;
        let state = state(env)?;
        let a = args.values;
        match args.operation {
            1 => submit(state, || {
                let (public, private) = core::generate_encryption_key_pair()?;
                Ok(Output::Pair(
                    Key::EncryptionPublic(Arc::new(public)),
                    Key::EncryptionPrivate(Secret::new(private)),
                ))
            }),
            2 => submit(state, || {
                let (public, private) = core::generate_signing_key_pair()?;
                Ok(Output::Pair(
                    Key::SigningPublic(Arc::new(public)),
                    Key::SigningPrivate(Secret::new(private)),
                ))
            }),
            operation @ 3..=6 => {
                let limit = [1578, 74, 2602, 42][operation - 3];
                let input = copy_bytes(env, a[0], limit, "ERR_INVALID_KEY");
                submit(state, move || {
                    let input = input?;
                    Ok(Output::Key(match operation {
                        3 => Key::EncryptionPublic(Arc::new(
                            core::EncryptionPublicKey::from_bytes(&input)?,
                        )),
                        4 => Key::EncryptionPrivate(Secret::new(
                            core::EncryptionPrivateKey::from_bytes(&input)?,
                        )),
                        5 => Key::SigningPublic(Arc::new(core::SigningPublicKey::from_bytes(
                            &input,
                        )?)),
                        6 => Key::SigningPrivate(Secret::new(core::SigningPrivateKey::from_bytes(
                            &input,
                        )?)),
                        _ => return Err(internal()),
                    }))
                })
            }
            7 => {
                let Key::EncryptionPublic(key) = key(&state, a[0], 0)? else {
                    return Err(invalid());
                };
                let aad = option_bytes(
                    env,
                    a[2],
                    c"aad",
                    core::MAX_AAD_LEN,
                    "ERR_MESSAGE_TOO_LARGE",
                );
                if pending(env) {
                    return Err(internal());
                }
                let message = copy_bytes(env, a[1], core::MAX_MESSAGE_LEN, "ERR_MESSAGE_TOO_LARGE");
                submit(state, move || {
                    Ok(bytes(core::encrypt(&key, &message?, &aad?)?))
                })
            }
            8 => {
                let Key::EncryptionPrivate(key) = key(&state, a[0], 1)? else {
                    return Err(invalid());
                };
                let aad = option_bytes(
                    env,
                    a[2],
                    c"aad",
                    core::MAX_AAD_LEN,
                    "ERR_MESSAGE_TOO_LARGE",
                );
                if pending(env) {
                    return Err(internal());
                }
                let envelope =
                    copy_bytes(env, a[1], core::MAX_ENVELOPE_LEN, "ERR_MESSAGE_TOO_LARGE");
                submit(state, move || {
                    let aad = aad?;
                    let envelope = envelope?;
                    key.with(|key| Ok(bytes(core::decrypt(key, &envelope, &aad)?)))
                })
            }
            9 => {
                let Key::SigningPrivate(key) = key(&state, a[0], 3)? else {
                    return Err(invalid());
                };
                let context = option_bytes(
                    env,
                    a[2],
                    c"context",
                    core::MAX_CONTEXT_LEN,
                    "ERR_CONTEXT_TOO_LONG",
                );
                if pending(env) {
                    return Err(internal());
                }
                let message = copy_bytes(env, a[1], core::MAX_MESSAGE_LEN, "ERR_MESSAGE_TOO_LARGE");
                submit(state, move || {
                    let context = context?;
                    let message = message?;
                    key.with(|key| Ok(bytes(core::sign(key, &message, &context)?)))
                })
            }
            10 => {
                let Key::SigningPublic(key) = key(&state, a[0], 2)? else {
                    return Err(invalid());
                };
                let context = option_bytes(
                    env,
                    a[3],
                    c"context",
                    core::MAX_CONTEXT_LEN,
                    "ERR_CONTEXT_TOO_LONG",
                );
                if pending(env) {
                    return Err(internal());
                }
                let message = copy_bytes(env, a[1], core::MAX_MESSAGE_LEN, "ERR_MESSAGE_TOO_LARGE");
                let signature = copy_bytes(
                    env,
                    a[2],
                    core::HEADER_LEN + core::SIGNATURE_LEN + 1,
                    "ERR_SIGNATURE_TOO_LARGE",
                );
                submit(state, move || {
                    let message = message?;
                    let context = context?;
                    match signature {
                        Err(error) if error.code == "ERR_SIGNATURE_TOO_LARGE" => {
                            Ok(Output::Bool(false))
                        }
                        Err(error) => Err(error),
                        Ok(signature) => Ok(Output::Bool(core::verify(
                            &key, &message, &signature, &context,
                        )?)),
                    }
                })
            }
            operation @ 20..=23 => {
                let key = key(&state, args.receiver, operation - 20)?;
                submit(state, move || key.export())
            }
            operation @ (31 | 33) => {
                let key = key(&state, args.receiver, operation - 30)?;
                key.revoke()?; // synchronous revocation, asynchronous lock/erasure
                submit(state, move || key.erase())
            }
            operation @ (41 | 43) => boolean(
                env,
                key(&state, args.receiver, operation - 40)?.destroyed()?,
            ),
            #[cfg(feature = "validation-hooks")]
            100 => {
                let mut fault = 0;
                check(napi_get_value_uint32(env, a[0], &mut fault))?;
                if !(1..=5).contains(&fault) {
                    return Err(invalid());
                }
                state.fault.set(fault);
                undefined(env)
            }
            #[cfg(feature = "validation-hooks")]
            101 => number(env, state.pending_count() as u32),
            #[cfg(feature = "validation-hooks")]
            102 => resources(env),
            _ => Err(invalid()),
        }
    })
}

unsafe fn initialize(env: Env, exports: Value) -> Result<Value> {
    let mut version = 0;
    check(unsafe { napi_get_version(env, &mut version) })?;
    if version < 8 {
        return Err(Failure::new(
            "ERR_NATIVE_BINDING_UNAVAILABLE",
            "Node-API 8 is required",
        ));
    }
    let state = unsafe { install_state(env) }?;
    let names: [&CStr; 4] = [
        c"EncryptionPublicKey",
        c"EncryptionPrivateKey",
        c"SigningPublicKey",
        c"SigningPrivateKey",
    ];
    let mut properties = Vec::new();
    for (kind, name) in names.into_iter().enumerate() {
        properties.push(Property::value(name, unsafe {
            register_class(&state, name, kind, callback)
        }?));
    }
    for (name, value) in [
        (c"MAX_MESSAGE_LEN", core::MAX_MESSAGE_LEN),
        (c"MAX_AAD_LEN", core::MAX_AAD_LEN),
        (c"MAX_CONTEXT_LEN", core::MAX_CONTEXT_LEN),
        (c"MAX_ENVELOPE_LEN", core::MAX_ENVELOPE_LEN),
    ] {
        properties.push(Property::value(name, unsafe { number(env, value as u32) }?));
    }
    for (index, name) in [
        c"generateEncryptionKeyPair",
        c"generateSigningKeyPair",
        c"importEncryptionPublicKey",
        c"importEncryptionPrivateKey",
        c"importSigningPublicKey",
        c"importSigningPrivateKey",
        c"encrypt",
        c"decrypt",
        c"sign",
        c"verify",
    ]
    .into_iter()
    .enumerate()
    {
        let mut descriptor = Property::method(name, callback, index + 1);
        descriptor.attributes = DEFAULT_PROPERTY;
        properties.push(descriptor);
    }
    #[cfg(feature = "validation-hooks")]
    {
        properties.push(Property::method(c"__setFault", callback, 100));
        properties.push(Property::method(c"__pendingJobs", callback, 101));
        properties.push(Property::method(c"__resources", callback, 102));
    }
    check(unsafe { napi_define_properties(env, exports, properties.len(), properties.as_ptr()) })?;
    Ok(exports)
}

/// The loader requests precisely the stable API version used by this adapter.
#[unsafe(no_mangle)]
pub extern "C" fn node_api_module_get_api_version_v1() -> i32 {
    8
}

/// # Safety
/// Node invokes this entry point with its live environment and exports object.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn napi_register_module_v1(env: Env, exports: Value) -> Value {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        if let Err(error) = ffi::initialize() {
            #[cfg(windows)]
            if let Ok(error) = std::ffi::CString::new(error) {
                unsafe {
                    ffi::bootstrap_error(env, &error);
                }
            }
            #[cfg(not(windows))]
            let _ = error;
            return null_mut();
        }
        boundary(env, || unsafe { initialize(env, exports) })
    }))
    .unwrap_or(null_mut())
}
