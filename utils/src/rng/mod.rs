//! Cryptographically secure random number generation
//! Constant-time operations only

use rand_core::{CryptoRng, RngCore};

/// Secure RNG trait for Aegis-Q
pub trait SecureRng: CryptoRng + RngCore {}

impl<T: CryptoRng + RngCore> SecureRng for T {}

/// Thread-local secure RNG instance
pub fn secure_rng() -> impl SecureRng {
    rand::thread_rng()
}

/// Generate random bytes
pub fn random_bytes(len: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; len];
    rand::thread_rng().fill_bytes(&mut bytes);
    bytes
}

/// Generate random u32
pub fn random_u32() -> u32 {
    rand::random()
}

/// Generate random u64
pub fn random_u64() -> u64 {
    rand::random()
}

