//! YSC1 (Yeun's Stream Cipher 1) Reference Implementation
//!
//! This implementation is compatible with the `cipher` crate traits and is based
//! on the (2x2) generalized Lai-Massey structure for Amaryllis-1024.

#![no_std]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/8f1a9894/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/8f1a9894/logo.svg"
)]

pub use cipher; // Re-export cipher crate for downstream users

use crate::core::Ysc1Core;
use cfg_if::cfg_if;

// --- Module declarations ---
mod arx;
mod backends;
mod core;

// --- CPU Feature Detection Tokens ---
cfg_if! {
    if #[cfg(all(any(target_arch = "x86", target_arch = "x86_64"), not(ysc1_force_soft)))] {
        cpufeatures::new!(avx2_cpuid, "avx2");
        type Tokens = avx2_cpuid::InitToken;
    } else {
        type Tokens = ();
    }
}

// --- Security Parameter Abstraction ---

/// A trait to define the security parameters for a YSC1 variant.
pub trait Ysc1Variant {
    /// Key size type and const.
    type KeySize: cipher::array::ArraySize;
    const KEY_SIZE: usize;
    /// Nonce size type and const.
    type NonceSize: cipher::array::ArraySize;
    const NONCE_SIZE: usize;
    /// Number of initialization rounds (first stage).
    const INIT_ROUNDS_1: usize;
    /// Number of initialization rounds (second stage).
    const INIT_ROUNDS_2: usize;
}

/// YSC1 variant with a 512-bit key and 512-bit nonce.
#[derive(Clone)]
pub struct Ysc1_512;
impl Ysc1Variant for Ysc1_512 {
    type KeySize = cipher::consts::U64;
    type NonceSize = cipher::consts::U64;
    const INIT_ROUNDS_1: usize = 16;
    const INIT_ROUNDS_2: usize = 16;
    
    const KEY_SIZE: usize = 64;
    
    const NONCE_SIZE: usize = 64;
}

/// YSC1 variant with a 1024-bit key and 512-bit nonce.
#[derive(Clone)]
pub struct Ysc1_1024;
impl Ysc1Variant for Ysc1_1024 {
    type KeySize = cipher::consts::U128;
    type NonceSize = cipher::consts::U64;
    const INIT_ROUNDS_1: usize = 20;
    const INIT_ROUNDS_2: usize = 20;
    
    const KEY_SIZE: usize = 128;
    
    const NONCE_SIZE: usize = 64;
}

// --- Convenience Type Aliases for Users ---
pub type Ysc1_512_Cipher = cipher::StreamCipherCoreWrapper<Ysc1Core<Ysc1_512>>;
pub type Ysc1_1024_Cipher = cipher::StreamCipherCoreWrapper<Ysc1Core<Ysc1_1024>>;
