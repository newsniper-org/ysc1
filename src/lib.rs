//! YSC1 (Yeun's Stream Cipher 1) Reference Implementation
//!
//! This implementation is compatible with the `cipher` crate traits and is based
//! on the (2x2) generalized Lai-Massey structure for Amaryllis-1024.

#![no_std]
// Enable the portable_simd feature for platform-agnostic SIMD.
#![cfg_attr(feature = "ysc1_simd", feature(portable_simd))]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/8f1a9894/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/8f1a9894/logo.svg"
)]

pub use cipher; // Re-export cipher crate for downstream users

use crate::core::Ysc1Core;

// --- Module declarations ---
mod arx;
mod backends;
mod core;

// --- Security Parameter Abstraction ---

/// A trait to define the security parameters for a YSC1 variant.
pub trait Ysc1Variant {
    /// Key size type and const.
    type KeySize: cipher::ArrayLength<u8>;
    const KEY_SIZE: usize;
    /// Nonce size type and const.
    type NonceSize: cipher::ArrayLength<u8>;
    const NONCE_SIZE: usize;
    /// Number of initialization rounds (for each of the two stages).
    const INIT_ROUNDS: usize;
    /// Number of rounds for keystream generation.
    const KEYSTREAM_ROUNDS: usize;
}

/// YSC1 variant with a 512-bit key and 512-bit nonce.
#[derive(Clone)]
pub struct Ysc1_512;
impl Ysc1Variant for Ysc1_512 {
    type KeySize = cipher::consts::U64;
    type NonceSize = cipher::consts::U64;
    const INIT_ROUNDS: usize = 16;
    const KEYSTREAM_ROUNDS: usize = 1; // Lai-Massey uses 1 round per block
    
    const KEY_SIZE: usize = 64;
    
    const NONCE_SIZE: usize = 64;
}

/// YSC1 variant with a 1024-bit key and 512-bit nonce.
#[derive(Clone)]
pub struct Ysc1_1024;
impl Ysc1Variant for Ysc1_1024 {
    type KeySize = cipher::consts::U128;
    type NonceSize = cipher::consts::U64;
    const INIT_ROUNDS: usize = 20;
    const KEYSTREAM_ROUNDS: usize = 1;
    
    const KEY_SIZE: usize = 128;
    
    const NONCE_SIZE: usize = 64;
}

// --- Convenience Type Aliases for Users ---
pub type Ysc1_512Cipher = cipher::StreamCipherCoreWrapper<Ysc1Core<Ysc1_512>>;
pub type Ysc1_1024Cipher = cipher::StreamCipherCoreWrapper<Ysc1Core<Ysc1_1024>>;
