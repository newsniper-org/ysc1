use crate::{arx, core::Ysc1Core, Ysc1Variant};
use cipher::{Block, BlockSizeUser, ParBlocksSizeUser, StreamBackend};
use core::simd::prelude::*;

/// The portable SIMD backend for YSC1.
pub struct Backend<'a, V: Ysc1Variant>(pub(crate) &'a mut Ysc1Core<V>);

impl<'a, V: Ysc1Variant> BlockSizeUser for Backend<'a, V> {
    type BlockSize = cipher::consts::U64;
}

// Re-add ParBlocksSizeUser for compatibility with cipher v0.4.4
impl<'a, V: Ysc1Variant> ParBlocksSizeUser for Backend<'a, V> {
    type ParBlocksSize = cipher::consts::U64;
}

impl<'a, V: Ysc1Variant> StreamBackend for Backend<'a, V> {
    #[inline]
    fn gen_ks_block(&mut self, block: &mut Block<Self>) {
        self.0.counter = self.0.counter.wrapping_add(1);

        let mut working_state = self.0.state;
        working_state[0] ^= self.0.counter;

        for _ in 0..V::KEYSTREAM_ROUNDS {
            permutation_simd(&mut working_state);
        }

        let keystream_s_l = &working_state[0..8];
        for (i, chunk) in block.chunks_exact_mut(8).enumerate() {
            chunk.copy_from_slice(&keystream_s_l[i].to_le_bytes());
        }
    }
}

/// The state permutation function using portable SIMD.
#[inline(always)]
fn permutation_simd(state: &mut [u64; 16]) {
    // Load state blocks A, B, C, D into SIMD vectors.
    // We use u64x4, which corresponds to 256-bit vectors.
    let a = u64x4::from_slice(&state[0..4]);
    let b = u64x4::from_slice(&state[4..8]);
    let c = u64x4::from_slice(&state[8..12]);
    let d = u64x4::from_slice(&state[12..16]);

    // 1. Calculate Difference Vector: Δ = (A ⊕ C) || (B ⊕ D)
    let delta_l = a ^ c;
    let delta_r = b ^ d;

    // 2. Apply Round Function: T = ARX(Δ)
    let (t_l, t_r) = arx::arx_round_simd(delta_l, delta_r);

    // 3. State Update
    let state_a = a ^ t_l;
    let state_b = b ^ t_r;
    let state_c = c ^ t_l;
    let state_d = d ^ t_r;

    // Store results back to a temporary array to perform the scalar rotation.
    let mut temp_state = [0u64; 16];
    state_a.write_to_slice(&mut temp_state[0..4]);
    state_b.write_to_slice(&mut temp_state[4..8]);
    state_c.write_to_slice(&mut temp_state[8..12]);
    state_d.write_to_slice(&mut temp_state[12..16]);

    // 4. Apply Half-Round Function σ (Linear Permutation)
    temp_state.rotate_left(1);
    *state = temp_state;
}
