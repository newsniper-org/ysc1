/// The ARX (Add-Rotate-XOR) round function as specified.
/// It operates on a 512-bit block (8 x u64).
#[inline(always)]
pub(crate) fn arx_round(x: &mut [u64; 8]) {
    const R: [u32; 8] = [11, 12, 13, 14, 15, 16, 17, 18];
    const S: [u32; 8] = [7, 9, 11, 13, 15, 17, 19, 21];

    let mut a = [0u64; 8];
    let mut b = [0u64; 8];

    // First ARX layer
    for i in 0..8 {
        a[i] = (x[i].wrapping_add(x[(i + 1) & 7])).rotate_left(R[i]);
    }

    // Second ARX layer
    for i in 0..8 {
        b[i] = (a[i] ^ a[(i + 2) & 7]).rotate_left(S[i]);
    }

    *x = b;
}
