use crate::{backends, Tokens, Ysc1Variant};
use cfg_if::cfg_if;
use cipher::{
    BlockSizeUser, Iv, IvSizeUser, Key, KeyIvInit, KeySizeUser, StreamCipherCore,
    StreamCipherSeekCore,
};
use core::marker::PhantomData;

/// The core state for the YSC1 cipher.
pub struct Ysc1Core<V: Ysc1Variant> {
    /// Internal state of the core function
    pub(crate) state: [u64; 16],
    /// Block counter
    pub(crate) counter: u64,
    /// CPU target feature tokens
    #[allow(dead_code)]
    pub(crate) tokens: Tokens,
    /// PhantomData to tie the struct to the Ysc1Variant
    pub(crate) _variant: PhantomData<V>,
}

impl<V: Ysc1Variant> KeySizeUser for Ysc1Core<V> {
    type KeySize = V::KeySize;
}

impl<V: Ysc1Variant> IvSizeUser for Ysc1Core<V> {
    type IvSize = V::NonceSize;
}

impl<V: Ysc1Variant> BlockSizeUser for Ysc1Core<V> {
    type BlockSize = cipher::consts::U64; // 512-bit blocks
}

impl<V: Ysc1Variant> KeyIvInit for Ysc1Core<V> {
    fn new(key: &Key<Self>, iv: &Iv<Self>) -> Self {
        let mut state = [0u64; 16];
        let (s_l, s_r) = state.split_at_mut(8);

        let key_len = V::KEY_SIZE;
        let key_half_len = key_len / 2;
        let (key_l_bytes, key_r_bytes) = key.split_at(key_half_len);

        // 1. Load Nonce into S_L and K_R into S_R.
        for (i, chunk) in iv.chunks_exact(8).enumerate() {
            s_l[i] = u64::from_le_bytes(chunk.try_into().unwrap());
        }
        for (i, chunk) in key_r_bytes.chunks_exact(8).enumerate() {
            s_r[i] = u64::from_le_bytes(chunk.try_into().unwrap());
        }

        // 2. Run the permutation for INIT_ROUNDS_1 rounds.
        for _ in 0..V::INIT_ROUNDS_1 {
            backends::soft::permutation(&mut state);
        }

        // 3. XOR K_L into S_R.
        let (_, s_r) = state.split_at_mut(8);
        for (i, chunk) in key_l_bytes.chunks_exact(8).enumerate() {
            s_r[i] ^= u64::from_le_bytes(chunk.try_into().unwrap());
        }

        // 4. Run the permutation for INIT_ROUNDS_2 rounds.
        for _ in 0..V::INIT_ROUNDS_2 {
            backends::soft::permutation(&mut state);
        }

        cfg_if! {
            if #[cfg(all(any(target_arch = "x86", target_arch = "x86_64"), not(ysc1_force_soft)))] {
                let tokens = crate::avx2_cpuid::init();
            } else {
                let tokens = ();
            }
        }

        Self {
            state,
            counter: 0,
            tokens,
            _variant: PhantomData,
        }
    }
}

impl<V: Ysc1Variant> StreamCipherCore for Ysc1Core<V> {
    fn process_with_backend(&mut self, f: impl cipher::StreamCipherClosure<BlockSize = Self::BlockSize>) {
        cfg_if! {
            if #[cfg(all(any(target_arch = "x86", target_arch = "x86_64"), not(ysc1_force_soft)))] {
                if self.tokens.get() {
                    // In a full implementation, you would call the AVX2 backend here.
                    // f.call(&mut backends::avx2::Backend(self));
                    f.call(&mut backends::soft::Backend(self)); // Fallback for now
                } else {
                    f.call(&mut backends::soft::Backend(self));
                }
            } else {
                f.call(&mut backends::soft::Backend(self));
            }
        }
    }
    
    fn remaining_blocks(&self) -> Option<usize> {
        None
    }
}

impl<V: Ysc1Variant> StreamCipherSeekCore for Ysc1Core<V> {
    type Counter = u64;

    fn get_block_pos(&self) -> Self::Counter {
        self.counter
    }

    fn set_block_pos(&mut self, pos: Self::Counter) {
        self.counter = pos;
    }
}
