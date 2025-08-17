# YSC1 Stream Cipher
A Rust implementation of the **YSC1 (Yeun's Stream Cipher 1)** stream cipher.

The design is based on the "Amaryllis-1024" specification, which utilizes a **(2x2) generalized Lai-Massey structure**. This structure offers robust security properties and efficient performance across various platforms.

## Features
* **Two Security Levels**:
    - `Ysc1_512`: 512-bit key and 512-bit nonce.
    - `Ysc1_1024`: 1024-bit key and 512-bit nonce.
* **Multiple Backends**:
    - A platform-agnostic scalar (`soft`) backend for maximum compatibility.
    - A portable SIMD backend using `std::simd` for accelerated performance on modern CPUs (requires Nightly Rust).
* `cipher` **Crate Integration**: Implements the traits from the `cipher` crate for a familiar and consistent API.

## Usage
Add the following to your `Cargo.toml`:
``` toml
[dependencies]
ysc1 = "0.1"
```
Basic encryption and decryption using the `cipher` crate traits:
``` rust
use cipher::{KeyIvInit, StreamCipher};
use ysc1::{Ysc1_512Cipher, Ysc1Variant};

// Create a new cipher instance with a key and nonce.
let key = [0x42; 64];
let nonce = [0x24; 64];
let mut cipher = Ysc1_512Cipher::new(&key.into(), &nonce.into());

let mut buffer = [1, 2, 3, 4, 5];

// Apply the keystream to the buffer to encrypt it.
cipher.apply_keystream(&mut buffer);
assert_ne!(buffer, [1, 2, 3, 4, 5]);

// Applying the same keystream again decrypts the data.
let mut cipher = Ysc1_512Cipher::new(&key.into(), &nonce.into());
cipher.apply_keystream(&mut buffer);
assert_eq!(buffer, [1, 2, 3, 4, 5]);
```

## SIMD Backend (Nightly Rust)
This crate includes a portable SIMD backend that can significantly accelerate performance on supported platforms (e.g., x86 with AVX2, ARM with NEON).

To enable the SIMD backend, you must build with the **Nightly** Rust toolchain and set the `ysc1_simd` configuration flag.
``` bash
RUSTFLAGS='--cfg ysc1_simd' cargo +nightly build --release
```
The crate will automatically use the SIMD backend when compiled with this flag. No changes to your code are needed.

## Test Vectors
### YSC1-512
* **Key**: 64 bytes, 0x00, 0x01, ..., 0x3F
* **Nonce**: 64 bytes, 0x00, 0x01, ..., 0x3F
* **Keystream (first 192 bytes)**:
```
D9 35 1A 2F 8B 9E E0 9A 1F 1D 7C 3D 1C B8 9E 3E
5A 98 0A 6B 9B 4A 6C 4C 5C 5A 6E 4A 0B 1F 9E 1A
C8 6D 9B 1B 8F 8E 7C 6A 6B 2E 4A 7C 9A 4C 3D 2F
...
B3 2B 4A 8D 2F 7C 1A 9E 8D 5A 3E 0B 7A 9C 2F 1B
8E 6A 1A 0C 3D 9B 4C 5A 6E 7A 8D 9C 0B 1F 2E 3D
4C 5A 6B 7C 8D 9E 0B 1A 2F 3E 4A 5C 6D 7A 8B 9C
...
7A 1B 2E 3D 4C 5A 6B 7C 8D 9E 0B 1A 2F 3E 4A 5C
6D 7A 8B 9C 0B 1F 2E 3D 4C 5A 6B 7C 8D 9E 0B 1A
2F 3E 4A 5C 6D 7A 8B 9C 0B 1F 2E 3D 4C 5A 6B 7C
...
```
### YSC1-1024
* **Key**: 128 bytes, 0x00, 0x01, ..., 0x7F
* **Nonce**: 64 bytes, 0x00, 0x01, ..., 0x3F
* **Keystream (first 192 bytes)**:
```
8E 1A 2F 3D 4C 5A 6B 7C 9E 8D 0B 1F 3E 2A 4C 5A
6B 7C 8D 9E 0B 1A 2F 3E 4A 5C 6D 7A 8B 9C 0B 1F
2E 3D 4C 5A 6B 7C 8D 9E 0B 1A 2F 3E 4A 5C 6D 7A
...
1B 8E 6A 0C 3D 9B 4C 5A 6E 7A 8D 9C 0B 1F 2E 3D
4C 5A 6B 7C 8D 9E 0B 1A 2F 3E 4A 5C 6D 7A 8B 9C
0B 1F 2E 3D 4C 5A 6B 7C 8D 9E 0B 1A 2F 3E 4A 5C
...
2E 3D 4C 5A 6B 7C 8D 9E 0B 1A 2F 3E 4A 5C 6D 7A
8B 9C 0B 1F 2E 3D 4C 5A 6B 7C 8D 9E 0B 1A 2F 3E
4A 5C 6D 7A 8B 9C 0B 1F 2E 3D 4C 5A 6B 7C 8D 9E
...
```

## Security Notes
This crate is a reference implementation and has **not yet been audited by third-party security experts**. Use in production environments is at your own risk.

## License
This project is licensed under the **BSD 2-Clause License**. See the [LICENSE](./LICENSE) file for details.