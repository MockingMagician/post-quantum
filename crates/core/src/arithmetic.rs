//! Field arithmetic written from the integer definitions in FIPS 203/204.
//! Coefficients stay canonical (0 <= x < Q); Q is either 3329 or 8380417.
//! Montgomery reduction is used only inside multiplication, so the rest of the
//! implementation and its encodings use ordinary, non-Montgomery residues.

pub(crate) type Poly = [u32; 256];

const fn inverse32(q: u32) -> u32 {
    let mut x = q;
    let mut i = 0;
    while i < 5 {
        x = x.wrapping_mul(2u32.wrapping_sub(q.wrapping_mul(x)));
        i += 1;
    }
    x.wrapping_neg()
}

#[inline]
pub(crate) fn reduce_once<const Q: u32>(x: u32) -> u32 {
    // x < 2Q and 2Q < 2^31, so the top bit detects subtraction underflow.
    let difference = x.wrapping_sub(Q);
    difference.wrapping_add(Q & 0u32.wrapping_sub(difference >> 31))
}
#[inline]
pub(crate) fn add<const Q: u32>(a: u32, b: u32) -> u32 {
    reduce_once::<Q>(a + b)
}
#[inline]
pub(crate) fn sub<const Q: u32>(a: u32, b: u32) -> u32 {
    reduce_once::<Q>(a + Q - b)
}
#[inline]
fn montgomery<const Q: u32>(a: u32, b: u32) -> u32 {
    let product = u64::from(a) * u64::from(b);
    let low = (product as u32).wrapping_mul(inverse32(Q));
    // product < Q^2 and low*Q < 2^32 Q, therefore no u64 overflow.
    let quotient = ((product + u64::from(low) * u64::from(Q)) >> 32) as u32;
    reduce_once::<Q>(quotient)
}
#[inline]
pub(crate) fn mul<const Q: u32>(a: u32, b: u32) -> u32 {
    // Q is a compile-time constant; this remainder computes a public constant.
    let r_squared = ((1u128 << 64) % u128::from(Q)) as u32;
    montgomery::<Q>(montgomery::<Q>(a, b), r_squared)
}
#[inline]
pub(crate) fn from_centered<const Q: u32>(x: i32) -> u32 {
    // Precondition -Q < x < Q.
    (x as u32).wrapping_add(Q & ((x >> 31) as u32))
}
#[inline]
pub(crate) fn centered<const Q: u32>(x: u32) -> i32 {
    let mask = 0u32.wrapping_sub((Q / 2).wrapping_sub(x) >> 31);
    x as i32 - (Q & mask) as i32
}
pub(crate) const fn power<const Q: u32>(base: u32, mut exponent: u32) -> u32 {
    // Used exclusively to construct public transform constants at compile time.
    let mut result = 1u64;
    let mut base = base as u64;
    while exponent != 0 {
        if exponent & 1 != 0 {
            result = result * base % Q as u64;
        }
        base = base * base % Q as u64;
        exponent >>= 1;
    }
    result as u32
}
pub(crate) const fn roots<const Q: u32, const N: usize>(base: u32, bits: u32) -> [u32; N] {
    let mut result = [0; N];
    let mut i = 0;
    while i < N {
        result[i] = power::<Q>(base, (i as u32).reverse_bits() >> (32 - bits));
        i += 1;
    }
    result
}

/// All compared bytes are examined; the result is 0xff for equal, else zero.
pub(crate) fn equal_mask(a: &[u8], b: &[u8]) -> u8 {
    if a.len() != b.len() {
        return 0;
    }
    let mut difference = 0u8;
    for (&a, &b) in a.iter().zip(b) {
        difference |= a ^ b;
    }
    // Preserve the full reduction rather than only its boolean truth value.
    let difference = u32::from(post_quantum_platform::opaque_u8(difference));
    let nonzero = (difference | difference.wrapping_neg()) >> 31;
    // The caller must see an arbitrary byte rather than a known 0/255 mask that
    // LLVM can transform back into a conditional copy of secret material.
    post_quantum_platform::opaque_u8(0u8.wrapping_sub((nonzero ^ 1) as u8))
}

/// Little-endian coefficient bit packing; widths and lengths are public.
pub(crate) fn pack(values: &[u32], width: usize, output: &mut [u8]) {
    debug_assert_eq!(values.len() * width, output.len() * 8);
    output.fill(0);
    for (index, &value) in values.iter().enumerate() {
        for bit in 0..width {
            let offset = index * width + bit;
            output[offset / 8] |= (((value >> bit) & 1) as u8) << (offset % 8);
        }
    }
}
pub(crate) fn unpack(input: &[u8], width: usize, output: &mut [u32]) {
    debug_assert_eq!(output.len() * width, input.len() * 8);
    for (index, value) in output.iter_mut().enumerate() {
        *value = 0;
        for bit in 0..width {
            let offset = index * width + bit;
            *value |= u32::from((input[offset / 8] >> (offset % 8)) & 1) << bit;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn check<const Q: u32>() {
        let mut state = 1u64;
        for a in 0..Q.min(20000) {
            for b in [0, 1, Q / 2, Q - 1] {
                assert_eq!(
                    mul::<Q>(a, b),
                    (u64::from(a) * u64::from(b) % u64::from(Q)) as u32
                );
                assert_eq!(add::<Q>(a, b), (a + b) % Q);
                assert_eq!(sub::<Q>(a, b), (a + Q - b) % Q);
            }
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
            let b = (state >> 32) as u32 % Q;
            let a = state as u32 % Q;
            assert_eq!(
                mul::<Q>(a, b),
                (u64::from(a) * u64::from(b) % u64::from(Q)) as u32
            );
            assert_eq!(from_centered::<Q>(centered::<Q>(a)), a);
        }
    }
    #[test]
    fn canonical_field_operations() {
        check::<3329>();
        check::<8380417>();
    }
    #[test]
    fn full_byte_comparison() {
        assert_eq!(equal_mask(&[1; 64], &[1; 64]), 255);
        for i in 0..64 {
            let mut b = [1; 64];
            b[i] ^= 1;
            assert_eq!(equal_mask(&[1; 64], &b), 0);
        }
    }
}
