#[cfg(feature = "ysc1_simd")]
use core::simd::prelude::*;

/// The scalar ARX (Add-Rotate-XOR) round function.
#[inline(always)]
pub(crate) fn arx_round(x: &mut [u64; 8]) {
    const R: [u32; 8] = [11, 12, 13, 14, 15, 16, 17, 18];
    const S: [u32; 8] = [7, 9, 11, 13, 15, 17, 19, 21];
    let mut a = [0u64; 8];
    let mut b = [0u64; 8];
    for i in 0..8 {
        a[i] = (x[i].wrapping_add(x[(i + 1) & 7])).rotate_left(R[i]);
    }
    for i in 0..8 {
        b[i] = (a[i] ^ a[(i + 2) & 7]).rotate_left(S[i]);
    }
    *x = b;
}

/// The portable SIMD ARX round function.
#[cfg(feature = "ysc1_simd")]
#[inline(always)]
pub(crate) fn arx_round_simd(xl: u64x4, xr: u64x4) -> (u64x4, u64x4) {
    // Constants for rotation.
    const R_L: u64x4 = u64x4::from_array([11, 12, 13, 14]);
    const R_R: u64x4 = u64x4::from_array([15, 16, 17, 18]);
    const S_L: u64x4 = u64x4::from_array([7, 9, 11, 13]);
    const S_R: u64x4 = u64x4::from_array([15, 17, 19, 21]);

    const WORD_BITS: u64x4 = u64x4::splat(64);

    // Helper function for SIMD rotation.
    #[inline(always)]
    fn rotate_left(val: u64x4, amount: u64x4) -> u64x4 {
        (val << amount) | (val >> (WORD_BITS - amount))
    }

    // First ARX layer: a[i] = (x[i] + x[i+1]) <<< R[i]
    // Swizzle to get x[i+1]
    let x_p1_l = simd_swizzle!(xl, [1, 2, 3, 0]);
    let x_p1_r = simd_swizzle!(xr, [1, 2, 3, 0]);
    let x_p1_shuffled: u64x8 = simd_swizzle!(xl, xr, [1, 2, 3, 4, 5, 6, 7, 0]);
    
    let a_l = rotate_left(xl + x_p1_shuffled.extract::<0,4>(), R_L);
    let a_r = rotate_left(xr + x_p1_shuffled.extract::<4,4>(), R_R);
    
    // Second ARX layer: b[i] = (a[i] ^ a[i+2]) <<< S[i]
    let a_p2_shuffled: u64x8 = simd_swizzle!(a_l, a_r, [2, 3, 4, 5, 6, 7, 0, 1]);
    let b_l = rotate_left(a_l ^ a_p2_shuffled.extract::<0,4>(), S_L);
    let b_r = rotate_left(a_l ^ a_p2_shuffled.extract::<4,4>(), S_R);

    (b_l, b_r)
}
