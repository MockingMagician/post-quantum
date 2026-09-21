//! The small, local unsafe boundary for OS entropy and secret erasure.
//!
//! Written for this project against OS API documentation and Rust's volatile
//! memory contract. No third-party implementation is incorporated. This cannot
//! erase compiler-created copies, registers, swap, or memory owned by JavaScript.
#![deny(unsafe_op_in_unsafe_fn)]

use std::ops::{Deref, DerefMut};
use std::sync::atomic::{Ordering, compiler_fence};

/// Best-effort erasure of owned secret storage before its allocation is released.
pub trait Zeroize {
    fn zeroize(&mut self);
}

macro_rules! erase_integer {
    ($($integer:ty),+ $(,)?) => {$(
        impl Zeroize for $integer {
            fn zeroize(&mut self) {
                // SAFETY: self is a live, aligned, exclusively borrowed integer.
                // Zero is a valid representation of each listed integer type.
                unsafe { std::ptr::write_volatile(self, 0) };
                compiler_fence(Ordering::SeqCst);
            }
        }
    )+};
}
erase_integer!(
    u8, u16, u32, u64, u128, usize, i8, i16, i32, i64, i128, isize
);

/// Keep an 8-bit mask/reduction opaque at the optimizer boundary.
///
/// Used with a complete XOR/OR comparison result, before converting it to a
/// boolean, and with selection masks. Treating these as known booleans otherwise
/// introduced early exits and conditional copies in LLVM's release output.
/// This inhibits those observed transformations, but is NOT a language-level
/// constant-time proof: inspect emitted code for each compiler and target.
#[inline(never)]
pub fn opaque_u8(mut value: u8) -> u8 {
    // SAFETY: value is a live, initialized, aligned local byte. Both operations
    // remain within its allocation; no concurrent access is possible.
    let output = unsafe { std::ptr::read_volatile(&value) };
    unsafe { std::ptr::write_volatile(&mut value, 0) };
    compiler_fence(Ordering::SeqCst);
    output
}

impl<T: Zeroize> Zeroize for [T] {
    fn zeroize(&mut self) {
        for value in self {
            value.zeroize();
        }
    }
}
impl<T: Zeroize, const N: usize> Zeroize for [T; N] {
    fn zeroize(&mut self) {
        self.as_mut_slice().zeroize();
    }
}
impl<T: Zeroize> Zeroize for Vec<T> {
    fn zeroize(&mut self) {
        self.as_mut_slice().zeroize();
    }
}
impl<T: Zeroize + ?Sized> Zeroize for Box<T> {
    fn zeroize(&mut self) {
        (**self).zeroize();
    }
}

/// Erases the live elements of an owned value on every normal or unwinding drop.
///
/// Do not shrink/reallocate secret vectors: removed elements and old allocations
/// are no longer owned by this guard. Deliberately does not implement Clone/Debug.
pub struct Zeroizing<T: Zeroize>(T);
impl<T: Zeroize> Zeroizing<T> {
    pub fn new(value: T) -> Self {
        Self(value)
    }
}
impl<T: Zeroize> Deref for Zeroizing<T> {
    type Target = T;
    fn deref(&self) -> &T {
        &self.0
    }
}
impl<T: Zeroize> DerefMut for Zeroizing<T> {
    fn deref_mut(&mut self) -> &mut T {
        &mut self.0
    }
}
impl<T: Zeroize> AsRef<T> for Zeroizing<T> {
    fn as_ref(&self) -> &T {
        &self.0
    }
}
impl<T: Zeroize> AsMut<T> for Zeroizing<T> {
    fn as_mut(&mut self) -> &mut T {
        &mut self.0
    }
}
impl<T: Zeroize> Zeroize for Zeroizing<T> {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}
impl<T: Zeroize> Drop for Zeroizing<T> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// Fills the entire destination from the operating system or erases it on error.
/// No user-space PRNG, cached random stream, or fallback source is used.
#[allow(clippy::result_unit_err)] // The caller exposes one deliberately opaque RNG failure.
pub fn fill_random(destination: &mut [u8]) -> Result<(), ()> {
    fill_with(destination, os_read)
}

fn fill_with(
    destination: &mut [u8],
    mut read: impl FnMut(&mut [u8]) -> std::io::Result<usize>,
) -> Result<(), ()> {
    let mut filled = 0;
    while filled < destination.len() {
        match read(&mut destination[filled..]) {
            Ok(n) if n != 0 && n <= destination.len() - filled => filled += n,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            _ => {
                destination.zeroize();
                return Err(());
            }
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn os_read(destination: &mut [u8]) -> std::io::Result<usize> {
    unsafe extern "C" {
        fn getrandom(buffer: *mut std::ffi::c_void, length: usize, flags: u32) -> isize;
    }
    // A small request works on glibc and musl and avoids the API's large-read cap.
    let length = destination.len().min(256);
    // SAFETY: the pointer spans length writable bytes for the duration of the
    // synchronous call. flags=0 waits for initialization of the kernel CSPRNG.
    let result = unsafe { getrandom(destination.as_mut_ptr().cast(), length, 0) };
    if result < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(result as usize)
    }
}

#[cfg(target_os = "macos")]
fn os_read(destination: &mut [u8]) -> std::io::Result<usize> {
    unsafe extern "C" {
        fn getentropy(buffer: *mut std::ffi::c_void, length: usize) -> i32;
    }
    let length = destination.len().min(256);
    // SAFETY: getentropy accepts at most 256 writable bytes and is synchronous.
    let result = unsafe { getentropy(destination.as_mut_ptr().cast(), length) };
    if result == 0 {
        Ok(length)
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(target_os = "windows")]
fn os_read(destination: &mut [u8]) -> std::io::Result<usize> {
    #[link(name = "bcrypt")]
    unsafe extern "system" {
        fn BCryptGenRandom(
            algorithm: *mut std::ffi::c_void,
            buffer: *mut u8,
            length: u32,
            flags: u32,
        ) -> i32;
    }
    let length = destination.len().min(256);
    // SAFETY: BCRYPT_USE_SYSTEM_PREFERRED_RNG (2) requires the null handle;
    // the destination is valid for exactly length writable bytes during the call.
    let status = unsafe {
        BCryptGenRandom(
            std::ptr::null_mut(),
            destination.as_mut_ptr(),
            length as u32,
            2,
        )
    };
    if status == 0 {
        Ok(length)
    } else {
        Err(std::io::Error::other("operating-system randomness failed"))
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
compile_error!("Supported operating systems are Linux, macOS and Windows");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn erases_live_integer_and_nested_storage() {
        let mut bytes = [42u8; 65];
        bytes.zeroize();
        assert_eq!(bytes, [0; 65]);
        let mut coefficients = vec![[u32::MAX; 256]; 4];
        coefficients.zeroize();
        assert!(coefficients.iter().flatten().all(|x| *x == 0));
        let mut signed = i64::MIN;
        signed.zeroize();
        assert_eq!(signed, 0);
    }

    #[test]
    fn guard_erases_on_drop_and_unwind() {
        struct Observed<'a>(&'a mut [u8]);
        impl Zeroize for Observed<'_> {
            fn zeroize(&mut self) {
                self.0.zeroize();
            }
        }
        let mut bytes = [99; 8];
        {
            let _guard = Zeroizing::new(Observed(&mut bytes));
        }
        assert_eq!(bytes, [0; 8]);
        bytes.fill(77);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = Zeroizing::new(Observed(&mut bytes));
            panic!("injected");
        }));
        assert!(result.is_err());
        assert_eq!(bytes, [0; 8]);
    }

    #[test]
    fn entropy_retries_interruptions_and_completes_short_reads() {
        let mut output = [0; 10];
        let mut calls = 0;
        assert_eq!(
            fill_with(&mut output, |buffer| {
                calls += 1;
                if calls == 1 {
                    return Err(std::io::ErrorKind::Interrupted.into());
                }
                let n = buffer.len().min(3);
                buffer[..n].fill(0xA5);
                Ok(n)
            }),
            Ok(())
        );
        assert_eq!(calls, 5);
        assert_eq!(output, [0xA5; 10]);
    }

    #[test]
    fn entropy_zero_short_and_partial_failures_erase_all_bytes() {
        for mode in 0..4 {
            let mut output = [0xCC; 10];
            let mut calls = 0;
            assert_eq!(
                fill_with(&mut output, |buffer| {
                    calls += 1;
                    buffer[0] = 0xA5;
                    if mode == 0 {
                        return Ok(0);
                    }
                    if mode == 1 {
                        return Ok(buffer.len() + 1);
                    }
                    if mode == 3 && calls == 1 {
                        return Ok(1);
                    }
                    Err(std::io::ErrorKind::PermissionDenied.into())
                }),
                Err(())
            );
            assert_eq!(output, [0; 10]);
        }
    }

    #[test]
    fn os_entropy_handles_empty_and_multiple_chunks() {
        fill_random(&mut []).unwrap();
        let mut bytes = [0; 1025];
        fill_random(&mut bytes).unwrap();
        // Exercise the real API; this is not a statistical quality assessment.
    }
}
