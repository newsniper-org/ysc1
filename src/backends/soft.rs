use super::super::core::Ysc1Core;
use super::super::{Ysc1Variant, KEYSTREAM_WORDS, STATE_WORDS};
use cipher::{
    BlockBackend,
    inout::InOut,
    Block, BlockSizeUser, ParBlocksSizeUser,
    StreamBackend
};

/// The software backend for YSC1, wrapping the core logic.
pub struct Backend<'a, V: Ysc1Variant>(pub(crate) &'a mut Ysc1Core<V>);

impl<'a, V: Ysc1Variant> BlockSizeUser for Backend<'a, V> {
    type BlockSize = cipher::consts::U64;
}

impl<'a, V: Ysc1Variant> ParBlocksSizeUser for Backend<'a, V> {
    type ParBlocksSize = cipher::consts::U64;
}

impl<'a, V: Ysc1Variant> StreamBackend for Backend<'a, V> {
    fn gen_ks_block(&mut self, block: &mut Block<Self>) {
        // 1. Increment the counter word in the persistent state.
        self.0.state[12] = self.0.state[12].wrapping_add(1);
        assert!(self.0.state[12] != 0, "Counter overflow");

        // 2. Run rounds on a copy of the updated state.
        let final_state = run_rounds::<V>(&self.0.state);

        // 3. Generate keystream from the result.
        let mut keystream_bytes = [0u8; 64];
        for (chunk, val) in keystream_bytes.chunks_mut(8).zip(final_state[..KEYSTREAM_WORDS].iter()) {
            chunk.copy_from_slice(&val.to_le_bytes());
        }

        block.iter_mut().zip(keystream_bytes.iter()).for_each(|(b, &ks)| {
            *b ^= ks;
        });   
    }
}

impl<'a, V: Ysc1Variant> BlockBackend for Backend<'a, V> {
    fn proc_block(&mut self, mut block: InOut<'_, '_, Block<Self>>) {
        // 1. Increment the counter word in the persistent state.
        self.0.state[12] = self.0.state[12].wrapping_add(1);
        assert!(self.0.state[12] != 0, "Counter overflow");

        // 2. Run rounds on a copy of the updated state.
        let final_state = run_rounds::<V>(&self.0.state);

        // 3. Generate keystream from the result.
        let mut keystream_bytes = cipher::generic_array::GenericArray::default();
        for (chunk, val) in keystream_bytes.chunks_mut(8).zip(final_state[..KEYSTREAM_WORDS].iter()) {
            chunk.copy_from_slice(&val.to_le_bytes());
        }

        // 4. Apply keystream to the data block.
        block.xor_in2out(&keystream_bytes);
    }
}

/// Applies the core permutation for the specified number of rounds.
#[inline(always)]
fn run_rounds<V: Ysc1Variant>(state: &[u64; STATE_WORDS]) -> [u64; STATE_WORDS] {
    let mut temp_state = *state;
    for _ in 0..V::KEYSTREAM_ROUNDS {
        Ysc1Core::<V>::permutation_round(&mut temp_state);
    }
    temp_state
}