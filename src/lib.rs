//! YSC1 (Yeun's Stream Cipher 1) Scalar Reference Implementation
//!
//! This implementation is compatible with the `cipher` crate traits.
//! Its structure is inspired by the `chacha20` crate, separating the core
//! logic from the trait implementations.

#![no_std]

pub use cipher; // Re-export cipher crate for downstream users

use cfg_if::cfg_if;

use crate::core::Ysc1Core;

cfg_if! {
    if #[cfg(ysc1_force_soft)] {
        type Tokens = ();
    } else if #[cfg(any(target_arch = "x86", target_arch = "x86_64"))] {
        cfg_if! {
            if #[cfg(ysc1_force_avx2)] {
                #[cfg(not(target_feature = "avx2"))]
                compile_error!("You must enable `avx2` target feature with \
                    `ysc1_force_avx2` configuration option");
                type Tokens = ();
            } else if #[cfg(ysc1_force_sse2)] {
                #[cfg(not(target_feature = "sse2"))]
                compile_error!("You must enable `sse2` target feature with \
                    `ysc1_force_sse2` configuration option");
                type Tokens = ();
            } else {
                cpufeatures::new!(avx2_cpuid, "avx2");
                cpufeatures::new!(sse2_cpuid, "sse2");
                type Tokens = (avx2_cpuid::InitToken, sse2_cpuid::InitToken);
            }
        }
    } else {
        type Tokens = ();
    }
}

// --- Security Parameter Abstraction ---

/// A trait to define the security parameters for a YSC1 variant.
pub trait Ysc1Variant: Clone {
    const KEY_WORDS: usize;
    const NONCE_WORDS: usize;
    type KeySize: cipher::array::ArraySize;
    type NonceSize: cipher::array::ArraySize;
    const INIT_ROUNDS: usize;
    const KEYSTREAM_ROUNDS: usize;
}

/// YSC1 variant with a 512-bit key and 512-bit nonce.
#[derive(Clone)]
pub struct Ysc1_512;
impl Ysc1Variant for Ysc1_512 {
    const KEY_WORDS: usize = 8;
    const NONCE_WORDS: usize = 8;
    type KeySize = cipher::consts::U64;
    type NonceSize = cipher::consts::U64;
    const INIT_ROUNDS: usize = 16;
    const KEYSTREAM_ROUNDS: usize = 8;
}

/// YSC1 variant with a 1024-bit key and 512-bit nonce.
#[derive(Clone)]
pub struct Ysc1_1024;
impl Ysc1Variant for Ysc1_1024 {
    const KEY_WORDS: usize = 16;
    const NONCE_WORDS: usize = 8;
    type KeySize = cipher::consts::U128;
    type NonceSize = cipher::consts::U64;
    const INIT_ROUNDS: usize = 20;
    const KEYSTREAM_ROUNDS: usize = 10;
}

// --- Core Cipher Logic ---

pub(crate) mod core;

// --- Software Backend ---
pub(crate) mod backends;

// --- Constants ---
const STATE_WORDS: usize = 16;
const KEYSTREAM_WORDS: usize = 8;
const R1: u32 = 11;
const R2: u32 = 27;
const R3: u32 = 43;
const P: [usize; STATE_WORDS] = [0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11];

// --- Convenience Type Aliases for Users ---
pub type Ysc1Cipher512 = cipher::StreamCipherCoreWrapper<Ysc1Core<Ysc1_512>>;
pub type Ysc1Cipher1024 = cipher::StreamCipherCoreWrapper<Ysc1Core<Ysc1_1024>>;

// --- Tests ---
#[cfg(test)]
mod tests {
    use super::{Ysc1Cipher1024, Ysc1Cipher512};
    use cipher::{consts::{U128, U64}, KeyIvInit, StreamCipher};

    #[test]
    fn test_ysc1_512_encryption_decryption() {
        let key = cipher::array::Array::<u8, U64>::from([0x01; 64]);
        let nonce = cipher::array::Array::<u8, U64>::from([0x02; 64]);
        let mut plaintext = *b"This is a test message for YSC1-512 stream cipher.";
        let original_plaintext = plaintext;
        let mut cipher = Ysc1Cipher512::new(&key, &nonce);
        cipher.apply_keystream(&mut plaintext);
        assert_ne!(original_plaintext, plaintext);
        let mut cipher = Ysc1Cipher512::new(&key, &nonce);
        cipher.apply_keystream(&mut plaintext);
        assert_eq!(original_plaintext, plaintext);
    }

    #[test]
    fn test_ysc1_1024_keystream_generation() {
        let key = cipher::array::Array::<u8, U128>::from([0x03; 128]);
        let nonce = cipher::array::Array::<u8, U64>::from([0x04; 64]);
        let mut data1 = [0u8; 128];
        let mut data2 = [0u8; 128];
        let mut cipher1 = Ysc1Cipher1024::new(&key, &nonce);
        cipher1.apply_keystream(&mut data1);
        let mut cipher2 = Ysc1Cipher1024::new(&key, &nonce);
        cipher2.apply_keystream(&mut data2[..64]);
        assert_eq!(data1[..64], data2[..64]);
        assert_ne!(data1[..64], data1[64..]);
    }
}
