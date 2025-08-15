use crate::{arx::arx_round, core::Ysc1Core, Ysc1Variant};
use cipher::{Block, BlockSizeUser, ParBlocksSizeUser, StreamCipherBackend};

/// The software backend for YSC1.
pub struct Backend<'a, V: Ysc1Variant>(pub(crate) &'a mut Ysc1Core<V>);

impl<'a, V: Ysc1Variant> BlockSizeUser for Backend<'a, V> {
    type BlockSize = cipher::consts::U64;
}

impl<'a, V: Ysc1Variant> ParBlocksSizeUser for Backend<'a, V> {
    type ParBlocksSize = cipher::consts::U1;
}

impl<'a, V: Ysc1Variant> StreamCipherBackend for Backend<'a, V> {
    fn gen_ks_block(&mut self, block: &mut Block<Self>) {
        // 1. Increment counter before use.
        self.0.counter = self.0.counter.wrapping_add(1);

        // 2. Create a temporary working state.
        let mut working_state = self.0.state;

        // 3. Inject the counter into the working state.
        working_state[0] ^= self.0.counter;

        // 4. Update the working state using the permutation.
        permutation(&mut working_state);

        // 5. Generate keystream block Z = S_L from the result.
        let keystream_s_l = &working_state[0..8];
        for (i, chunk) in block.chunks_exact_mut(8).enumerate() {
            let keystream_chunk = keystream_s_l[i].to_le_bytes();
            chunk
                .iter_mut()
                .zip(keystream_chunk.iter())
                .for_each(|(b, &ks)| *b ^= ks);
        }

        // NOTE: The main state `self.0.state` is NOT modified during keystream generation,
        // only the counter is. This matches the repository's design pattern.
        // If the state itself needs to be updated per block, `self.0.state = working_state;`
        // would be added here.
    }
}



/// The state permutation function based on the (2x2) Lai-Massey structure.
/// This is the core cryptographic algorithm.
#[inline(always)]
pub(crate) fn permutation(state: &mut [u64; 16]) {
    let mut delta = [0u64; 8];

    // 1. Calculate Difference Vector: Δ = (A ⊕ C) || (B ⊕ D)
    for i in 0..4 {
        delta[i] = state[i] ^ state[i + 8];
        delta[i + 4] = state[i + 4] ^ state[i + 12];
    }

    // 2. Apply Round Function: T = ARX(Δ)
    arx_round(&mut delta);

    // 3. State Update
    for i in 0..4 {
        state[i] ^= delta[i];
        state[i + 4] ^= delta[i + 4];
        state[i + 8] ^= delta[i];
        state[i + 12] ^= delta[i + 4];
    }

    // 4. Apply Half-Round Function σ (Linear Permutation)
    state.rotate_left(1);
}
