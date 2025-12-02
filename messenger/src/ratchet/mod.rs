//! Double Ratchet Implementation
//! 
//! Post-quantum double ratchet for E2EE messaging
//! Uses Aegis-Q for encryption, no trusted centers

use aegis_q_core::{aegis_q_encrypt, aegis_q_decrypt};
use sha3::{Digest, Sha3_512};
use utils::kdf::kdf_shake256_fill;

/// Ratchet state
pub struct RatchetState {
    dh_private: Vec<u8>,
    dh_public: Vec<u8>,
    root_key: Vec<u8>,
    chain_key_send: Vec<u8>,
    chain_key_recv: Vec<u8>,
    message_number_send: u32,
    message_number_recv: u32,
}

impl RatchetState {
    /// Initialize ratchet state
    pub fn new(root_key: Vec<u8>) -> Self {
        // Generate DH key pair (simplified - in production use PQ KEM)
        let dh_private = vec![0u8; 32]; // Placeholder
        let dh_public = vec![0u8; 32]; // Placeholder
        
        let mut chain_key_send = vec![0u8; 64];
        let mut chain_key_recv = vec![0u8; 64];
        kdf_shake256_fill(b"aegis-q-messenger-ratchet-chain-send", &root_key, &[], &mut chain_key_send);
        kdf_shake256_fill(b"aegis-q-messenger-ratchet-chain-recv", &root_key, &[], &mut chain_key_recv);
        
        Self {
            dh_private,
            dh_public,
            root_key,
            chain_key_send,
            chain_key_recv,
            message_number_send: 0,
            message_number_recv: 0,
        }
    }
    
    /// Encrypt message
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Vec<u8> {
        // Derive message key
        let mut message_key = vec![0u8; 64];
        kdf_shake256_fill(
            b"aegis-q-messenger-ratchet-message-send",
            &self.chain_key_send,
            &self.message_number_send.to_le_bytes(),
            &mut message_key,
        );
        
        // Create nonce from message number
        let nonce = self.message_number_send.to_le_bytes().to_vec();
        
        // Encrypt
        let ciphertext = aegis_q_encrypt(&message_key, &nonce, plaintext);
        
        // Advance chain
        self.advance_send_chain();
        
        ciphertext
    }
    
    /// Decrypt message
    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, &'static str> {
        // Derive message key
        let mut message_key = vec![0u8; 64];
        kdf_shake256_fill(
            b"aegis-q-messenger-ratchet-message-recv",
            &self.chain_key_recv,
            &self.message_number_recv.to_le_bytes(),
            &mut message_key,
        );
        
        // Create nonce from message number
        let nonce = self.message_number_recv.to_le_bytes().to_vec();
        
        // Decrypt
        let plaintext = aegis_q_decrypt(&message_key, &nonce, ciphertext)?;
        
        // Advance chain
        self.advance_recv_chain();
        
        Ok(plaintext)
    }
    
    /// Advance send chain
    fn advance_send_chain(&mut self) {
        let mut hasher = Sha3_512::new();
        hasher.update(&self.chain_key_send);
        hasher.update(b"chain-advance");
        self.chain_key_send = hasher.finalize().to_vec();
        self.message_number_send += 1;
    }
    
    /// Advance receive chain
    fn advance_recv_chain(&mut self) {
        let mut hasher = Sha3_512::new();
        hasher.update(&self.chain_key_recv);
        hasher.update(b"chain-advance");
        self.chain_key_recv = hasher.finalize().to_vec();
        self.message_number_recv += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_ratchet_encrypt_decrypt() {
        let root_key = b"root-key-123456789012345678901234567890".to_vec();
        let mut ratchet = RatchetState::new(root_key);
        
        let plaintext = b"Hello, Ratchet!";
        let ciphertext = ratchet.encrypt(plaintext);
        
        // Create new ratchet with same root key for decryption
        let mut ratchet2 = RatchetState::new(b"root-key-123456789012345678901234567890".to_vec());
        let decrypted = ratchet2.decrypt(&ciphertext).unwrap();
        
        assert_eq!(plaintext, decrypted.as_slice());
    }
}

