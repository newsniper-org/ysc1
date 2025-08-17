//! # YSC1 (Yeun's Stream Cipher 1)
//!
//! This crate provides a Rust implementation of the **YSC1 stream cipher**.
//!
//! The design is based on the "Amaryllis-1024" specification, which utilizes a
//! **(2x2) generalized Lai-Massey structure**. This structure offers robust security
//! properties and efficient performance across various platforms.
//!
//! ## Features
//!
//! - **Two Security Levels**:
//!   - `Ysc1_512`: 512-bit key and 512-bit nonce.
//!   - `Ysc1_1024`: 1024-bit key and 512-bit nonce.
//! - **Multiple Backends**:
//!   - A platform-agnostic scalar (`soft`) backend.
//!   - A portable SIMD backend using `std::simd` for accelerated performance on
//!     modern CPUs (requires Nightly Rust).
//! - **`cipher` Crate Integration**: Implements the traits from the `cipher` crate
//!   for a familiar and consistent API.
//!
//! ## Usage
//!
//! Basic encryption and decryption using the `cipher` crate traits:
//!
//! ```
//! use ysc1::cipher::{KeyIvInit, StreamCipher};
//! use ysc1::{Ysc1_512Cipher, Ysc1Variant}; // Use Ysc1_1024_Cipher for the 1024-bit version
//!
//! // Create a new cipher instance with a key and nonce.
//! let key = [0x42; 64];
//! let nonce = [0x24; 64];
//! let mut cipher = Ysc1_512Cipher::new(&key.into(), &nonce.into());
//!
//! let mut buffer = [1, 2, 3, 4, 5];
//!
//! // Apply the keystream to the buffer to encrypt it.
//! cipher.apply_keystream(&mut buffer);
//! assert_ne!(buffer, [1, 2, 3, 4, 5]);
//!
//! // Applying the same keystream again decrypts the data.
//! let mut cipher = Ysc1_512Cipher::new(&key.into(), &nonce.into());
//! cipher.apply_keystream(&mut buffer);
//! assert_eq!(buffer, [1, 2, 3, 4, 5]);
//! ```


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

// --- Tests ---
#[cfg(test)]
mod tests {
    use super::{Ysc1_1024Cipher, Ysc1_512Cipher};
    use cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};

    const PLAINTEXT: &[u8] = b"This is a test message for the YSC1 stream cipher implementation.";

    #[test]
    fn ysc1_512_encrypt_decrypt() {
        let key = [0x01; 64].into();
        let nonce = [0x02; 64].into();
        let mut buffer = PLAINTEXT.to_vec();

        // Encrypt
        let mut cipher = Ysc1_512Cipher::new(&key, &nonce);
        cipher.apply_keystream(&mut buffer);

        assert_ne!(
            buffer, PLAINTEXT,
            "Ciphertext should not be the same as plaintext"
        );

        // Decrypt
        let mut cipher = Ysc1_512Cipher::new(&key, &nonce);
        cipher.apply_keystream(&mut buffer);

        assert_eq!(
            buffer, PLAINTEXT,
            "Decrypted text should match the original plaintext"
        );
    }

    #[test]
    fn ysc1_1024_seek_and_consistency() {
        let key = [0x03; 128].into();
        let nonce = [0x04; 64].into();
        let mut buffer1 = [0u8; 128];
        let mut buffer2 = [0u8; 128];

        // Generate 2 blocks of keystream
        let mut cipher1 = Ysc1_1024Cipher::new(&key, &nonce);
        cipher1.apply_keystream(&mut buffer1);

        // Generate the second block separately after seeking
        let mut cipher2 = Ysc1_1024Cipher::new(&key, &nonce);
        cipher2.seek(64); // Seek to the beginning of the second block
        cipher2.apply_keystream(&mut buffer2[64..]);

        assert_eq!(
            buffer1[64..],
            buffer2[64..],
            "Keystream from sought position should match"
        );
    }

    #[test]
    #[cfg(feature = "ysc1_simd")]
    fn ysc1_simd_vs_soft_consistency() {
        use crate::core::Ysc1Core;
        use crate::{Ysc1_512, backends};

        let key = [0xAB; 64].into();
        let nonce = [0xCD; 64].into();
        
        // Generate keystream using the soft backend
        let mut soft_cipher = Ysc1_512_Cipher::new(&key, &nonce);
        let mut soft_keystream = vec![0u8; 256];
        soft_cipher.apply_keystream(&mut soft_keystream);

        // Generate keystream using the SIMD backend
        // We need to build a core instance and call the backend directly for this test
        let mut simd_core = Ysc1Core::<Ysc1_512>::new(&key, &nonce);
        let mut simd_backend = backends::simd::Backend(&mut simd_core);
        let mut simd_keystream = vec![0u8; 256];
        for chunk in simd_keystream.chunks_mut(64) {
            cipher::StreamCipherBackend::gen_ks_block(&mut simd_backend, chunk.into());
        }

        assert_eq!(soft_keystream, simd_keystream, "SIMD and Soft backends must produce identical keystreams");
    }
}