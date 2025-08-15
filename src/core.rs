use core::marker::PhantomData;

use crate::{avx2_cpuid, sse2_cpuid};

use super::Tokens;
use super::{Ysc1Variant, P, R1, R2, R3, STATE_WORDS};
use cipher::{BlockSizeUser, Iv, IvSizeUser, Key, KeyIvInit, KeySizeUser, ParBlocksSizeUser, StreamCipherCore, StreamCipherSeekCore};
use cfg_if::cfg_if;
#[cfg(feature = "zeroize")]
use zeroize::ZeroizeOnDrop;

/// The core state for the YSC1 cipher.
/// This struct only holds the internal state. All logic is in the backend.
pub struct Ysc1Core<V: Ysc1Variant> {
    /// Internal state of the core function
    pub(crate) state: [u64; STATE_WORDS],

    /// CPU target feature tokens
    #[allow(dead_code)]
    pub(crate) tokens: Tokens,
    pub(crate) _variant: core::marker::PhantomData<V>,
}

impl<V: Ysc1Variant> Ysc1Core<V> {
    /// The core state permutation function (1 round).
    pub(crate) fn permutation_round(state: &mut [u64; STATE_WORDS]) {
        Self::lm_quad_round(state, 0, 1, 2, 3);
        Self::lm_quad_round(state, 4, 5, 6, 7);
        Self::lm_quad_round(state, 8, 9, 10, 11);
        Self::lm_quad_round(state, 12, 13, 14, 15);

        let mut temp_state = *state;
        for i in 0..STATE_WORDS {
            temp_state[i] = state[P[i]];
        }
        *state = temp_state;
    }

    #[inline(always)]
    fn f_function(x: u64) -> u64 {
        let y = x.wrapping_add(x.rotate_left(R1));
        let z = y ^ y.rotate_left(R2);
        z.wrapping_add(z.rotate_left(R3))
    }
    
    #[inline(always)]
    fn lm_quad_round(state: &mut [u64; STATE_WORDS], i0: usize, i1: usize, i2: usize, i3: usize) {
        let (x0, x1, x2, x3) = (state[i0], state[i1], state[i2], state[i3]);
        let (t0, t1) = (Self::f_function(x0 ^ x2), Self::f_function(x1 ^ x3));
        let (y0, y1) = (x0.wrapping_add(t0), x1.wrapping_add(t1));
        let (y2, y3) = (x2.wrapping_add(t0), x3.wrapping_add(t1));
        state[i0] = y0 ^ y2;
        state[i1] = y1 ^ y3;
        state[i2] = y0;
        state[i3] = y1;
    }
}

impl<V: Ysc1Variant> StreamCipherCore for Ysc1Core<V> {
    fn remaining_blocks(&self) -> Option<usize> {
        None
    }
    
    fn process_with_backend(&mut self, f: impl cipher::StreamCipherClosure<BlockSize = Self::BlockSize>) {
        cfg_if! {
            if #[cfg(ysc1_force_soft)] {
                f.call(&mut backends::soft::Backend(self));
            } else if #[cfg(any(target_arch = "x86", target_arch = "x86_64"))] {
                cfg_if! {
                    if #[cfg(ysc1_force_avx2)] {
                        unimplemented!();
                    } else if #[cfg(ysc1_force_sse2)] {
                        unimplemented!();
                    } else {
                        let (avx2_token, sse2_token) = self.tokens;
                        if avx2_token.get() {
                            unimplemented!();
                        } else if sse2_token.get() {
                            unimplemented!();
                        } else {
                            f.call(&mut super::backends::soft::Backend(self));
                        }
                    }
                }
            } else if #[cfg(all(target_arch = "aarch64", target_feature = "neon"))] {
                unimplemented!();
            } else {
                f.call(&mut backends::soft::Backend(self));
            }
        }
    }

    
}

impl<V: Ysc1Variant> BlockSizeUser for Ysc1Core<V> {
    type BlockSize = cipher::consts::U64;
}

impl<V: Ysc1Variant> ParBlocksSizeUser for Ysc1Core<V> {
    type ParBlocksSize = cipher::consts::U64;
}

impl<V: Ysc1Variant> KeySizeUser for Ysc1Core<V> {
    type KeySize = V::KeySize;
}

impl<V: Ysc1Variant> IvSizeUser for Ysc1Core<V> {
    type IvSize = V::NonceSize;
}

impl<V: Ysc1Variant> KeyIvInit for Ysc1Core<V> {
    fn new(key: &Key<Self>, iv: &Iv<Self>) -> Self {
        let mut state = [0u64; STATE_WORDS];
        for (i, chunk) in key.chunks_exact(8).enumerate() {
            state[i] = u64::from_le_bytes(chunk.try_into().unwrap());
        }
        if V::KEY_WORDS + V::NONCE_WORDS <= STATE_WORDS {
            let nonce_start = V::KEY_WORDS;
            for (i, chunk) in iv.chunks_exact(8).enumerate() {
                state[nonce_start + i] = u64::from_le_bytes(chunk.try_into().unwrap());
            }
        } else {
            for (i, chunk) in iv.chunks_exact(8).enumerate() {
                state[i] ^= u64::from_le_bytes(chunk.try_into().unwrap());
            }
        }
        // Initialize counter word to 0. It will be incremented to 1 for the first block.
        state[12] = 0;

        cfg_if! {
            if #[cfg(ysc1_force_soft)] {
                let tokens = ();
            } else if #[cfg(any(target_arch = "x86", target_arch = "x86_64"))] {
                cfg_if! {
                    if #[cfg(ysc1_force_avx2)] {
                        let tokens = ();
                    } else if #[cfg(ysc1_force_sse2)] {
                        let tokens = ();
                    } else {
                        let tokens = (avx2_cpuid::init(), sse2_cpuid::init());
                    }
                }
            } else {
                let tokens = ();
            }
        }

        for _ in 0..V::INIT_ROUNDS {
            Ysc1Core::<V>::permutation_round(&mut state);
        }
        
        Self { tokens, state, _variant: PhantomData }
        
    }
}


impl<V: Ysc1Variant> StreamCipherSeekCore for Ysc1Core<V> {
    type Counter = u64;

    #[inline(always)]
    fn get_block_pos(&self) -> Self::Counter {
        self.state[12]
    }

    #[inline(always)]
    fn set_block_pos(&mut self, pos: Self::Counter) {
        self.state[12] = pos
    }
}

#[cfg(feature = "zeroize")]
impl<V: Ysc1Variant> Drop for Ysc1Core<V> {
    fn drop(&mut self) {
        self.state.zeroize();
    }
}

#[cfg(feature = "zeroize")]
impl<V: Ysc1Variant> ZeroizeOnDropDrop for Ysc1Core<V> {}