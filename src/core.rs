use crate::{backends, Ysc1Variant};
use cipher::{
    BlockSizeUser, Iv, IvSizeUser, Key, KeyIvInit, KeySizeUser, StreamCipherCore,
    StreamCipherSeekCore,
};
use core::marker::PhantomData;

/// The core stateful logic of the YSC1 cipher.
///
/// This struct holds the internal 1024-bit state and the block counter.
/// It implements the main `cipher` traits, delegating the cryptographic
/// permutation to a selected backend.
pub struct Ysc1Core<V: Ysc1Variant> {
    /// The 1024-bit internal state (16 x 64-bit words).
    pub(crate) state: [u64; 16],
    /// The 64-bit block counter.
    pub(crate) counter: u64,
    /// PhantomData to associate the core with a specific `Ysc1Variant`.
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
    /// Creates a new `Ysc1Core` instance, initializing its state with the
    /// given key and nonce according to the specification.
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

        // 2. Run the permutation for INIT_ROUNDS (stage 1).
        for _ in 0..V::INIT_ROUNDS {
            backends::soft::permutation(&mut state);
        }

        // 3. XOR K_L into S_R.
        let (_, s_r) = state.split_at_mut(8);
        for (i, chunk) in key_l_bytes.chunks_exact(8).enumerate() {
            s_r[i] ^= u64::from_le_bytes(chunk.try_into().unwrap());
        }

        // 4. Run the permutation for INIT_ROUNDS (stage 2).
        for _ in 0..V::INIT_ROUNDS {
            backends::soft::permutation(&mut state);
        }

        Self {
            state,
            counter: 0,
            _variant: PhantomData,
        }
    }
}

// In cipher v0.4.4, StreamCipherCore does not have a `remaining_blocks` method.
impl<V: Ysc1Variant> StreamCipherCore for Ysc1Core<V> {
    /// Returns `None` because YSC1 can produce a virtually infinite keystream.
    fn remaining_blocks(&self) -> Option<usize> {
        None
    }
    
    /// Processes data by applying the keystream, delegating the core permutation
    /// to the backend selected at compile time.
    fn process_with_backend(&mut self, f: impl cipher::StreamClosure<BlockSize = Self::BlockSize>) {
        cfg_if::cfg_if! {
            if #[cfg(feature = "ysc1_simd")] {
                f.call(&mut backends::simd::Backend(self));
            } else {
                f.call(&mut backends::soft::Backend(self));
            }
        }
    }
}

impl<V: Ysc1Variant> StreamCipherSeekCore for Ysc1Core<V> {
    type Counter = u64;

    /// Gets the current block position (counter).
    fn get_block_pos(&self) -> Self::Counter {
        self.counter
    }

    /// Sets the block position (counter).
    fn set_block_pos(&mut self, pos: Self::Counter) {
        self.counter = pos;
    }
}
