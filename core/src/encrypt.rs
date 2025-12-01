//! Aegis-Q Encryption/Decryption API
//! 
//! High-level API for encrypting and decrypting data using Aegis-Q

use crate::state::State;
use crate::round::{round, derive_round_keys, ROUNDS};
use sha3::{Digest, Shake256, digest::{Update, ExtendableOutput, XofReader}};

/// Initialize Aegis-Q state from key and nonce
pub fn aegis_q_init(key: &[u8], nonce: &[u8]) -> State {
    State::from_key(key, nonce)
}

/// Encrypt plaintext using Aegis-Q
/// 
/// # Arguments
/// * `key` - Encryption key (recommended: 32-64 bytes)
/// * `nonce` - Nonce (recommended: 16-32 bytes)
/// * `plaintext` - Plaintext to encrypt
/// 
/// # Returns
/// Ciphertext (same length as plaintext + authentication tag)
pub fn aegis_q_encrypt(key: &[u8], nonce: &[u8], plaintext: &[u8]) -> Vec<u8> {
    // Initialize state
    let mut state = aegis_q_init(key, nonce);
    
    // Derive round keys
    let round_keys = derive_round_keys(key, nonce, ROUNDS);
    
    // Apply rounds
    for i in 0..ROUNDS {
        round(&mut state, &round_keys[i], nonce, i as u64);
    }
    
    // Generate keystream using KDF
    let keystream = kdf(&state, plaintext.len());
    
    // XOR with plaintext
    let mut ciphertext = Vec::with_capacity(plaintext.len());
    for i in 0..plaintext.len() {
        ciphertext.push(plaintext[i] ^ keystream[i]);
    }
    
    // Generate authentication tag
    let tag = generate_tag(&state, &ciphertext);
    
    // Append tag to ciphertext
    ciphertext.extend_from_slice(&tag);
    
    ciphertext
}

/// Decrypt ciphertext using Aegis-Q
/// 
/// # Arguments
/// * `key` - Decryption key (must match encryption key)
/// * `nonce` - Nonce (must match encryption nonce)
/// * `ciphertext` - Ciphertext to decrypt (includes authentication tag)
/// 
/// # Returns
/// Plaintext or error if authentication fails
pub fn aegis_q_decrypt(key: &[u8], nonce: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, &'static str> {
    const TAG_SIZE: usize = 32; // 256-bit tag
    
    if ciphertext.len() < TAG_SIZE {
        return Err("Ciphertext too short");
    }
    
    let (encrypted_data, tag) = ciphertext.split_at(ciphertext.len() - TAG_SIZE);
    
    // Initialize state (same as encryption)
    let mut state = aegis_q_init(key, nonce);
    
    // Derive round keys
    let round_keys = derive_round_keys(key, nonce, ROUNDS);
    
    // Apply rounds
    for i in 0..ROUNDS {
        round(&mut state, &round_keys[i], nonce, i as u64);
    }
    
    // Verify tag
    let computed_tag = generate_tag(&state, encrypted_data);
    if computed_tag != tag {
        return Err("Authentication failed");
    }
    
    // Generate keystream
    let keystream = kdf(&state, encrypted_data.len());
    
    // XOR to decrypt
    let mut plaintext = Vec::with_capacity(encrypted_data.len());
    for i in 0..encrypted_data.len() {
        plaintext.push(encrypted_data[i] ^ keystream[i]);
    }
    
    Ok(plaintext)
}

/// Key Derivation Function (KDF)
/// Uses SHAKE-256 to derive keystream from state
fn kdf(state: &State, length: usize) -> Vec<u8> {
    let mut hasher = Shake256::default();
    hasher.update(&state.to_bytes());
    
    let mut reader = hasher.finalize_xof();
    let mut keystream = vec![0u8; length];
    reader.read(&mut keystream);
    
    keystream
}

/// Generate authentication tag
fn generate_tag(state: &State, data: &[u8]) -> Vec<u8> {
    use sha3::Sha3_256;
    
    let mut hasher = Sha3_256::new();
    hasher.update(&state.to_bytes());
    hasher.update(data);
    hasher.finalize().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_encrypt_decrypt() {
        let key = b"test-key-123456789012345678901234567890";
        let nonce = b"test-nonce-123456";
        let plaintext = b"Hello, Aegis-Q!";
        
        let ciphertext = aegis_q_encrypt(key, nonce, plaintext);
        assert_ne!(ciphertext, plaintext);
        
        let decrypted = aegis_q_decrypt(key, nonce, &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }
    
    #[test]
    fn test_encrypt_decrypt_long() {
        let key = b"test-key-123456789012345678901234567890";
        let nonce = b"test-nonce-123456";
        let plaintext = vec![0x42u8; 10000];
        
        let ciphertext = aegis_q_encrypt(key, nonce, &plaintext);
        let decrypted = aegis_q_decrypt(key, nonce, &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }
    
    #[test]
    fn test_authentication_failure() {
        let key = b"test-key-123456789012345678901234567890";
        let nonce = b"test-nonce-123456";
        let plaintext = b"Hello, Aegis-Q!";
        
        let mut ciphertext = aegis_q_encrypt(key, nonce, plaintext);
        
        // Tamper with ciphertext
        ciphertext[0] ^= 1;
        
        let result = aegis_q_decrypt(key, nonce, &ciphertext);
        assert!(result.is_err());
    }
}

