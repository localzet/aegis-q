//! Aegis-Q QUIC Implementation
//! 
//! QUIC-like protocol using Aegis-Q encryption
//! Session management and stream handling

use aegis_q_core::{aegis_q_encrypt, aegis_q_decrypt};
use crate::framing::Frame;
use sha3::{Digest, Sha3_512};
use hkdf::Hkdf;

/// QUIC session
pub struct QuicSession {
    session_key: Vec<u8>,
    session_nonce: Vec<u8>,
    stream_ids: Vec<u32>,
}

impl QuicSession {
    /// Create new QUIC session
    pub fn new(session_key: Vec<u8>, session_nonce: Vec<u8>) -> Self {
        Self {
            session_key,
            session_nonce,
            stream_ids: Vec::new(),
        }
    }
    
    /// Create new stream
    pub fn create_stream(&mut self) -> u32 {
        let stream_id = self.stream_ids.len() as u32;
        self.stream_ids.push(stream_id);
        stream_id
    }
    
    /// Encrypt stream data
    pub fn encrypt_stream(&self, stream_id: u32, data: &[u8], sequence: u64) -> Vec<u8> {
        // Derive stream-specific key
        let mut stream_key = vec![0u8; 64];
        let hk = Hkdf::<Sha3_512>::new(Some(&self.session_nonce), &self.session_key);
        hk.expand(&stream_id.to_le_bytes(), &mut stream_key).unwrap();
        
        // Create nonce with stream ID and sequence
        let mut nonce = self.session_nonce.clone();
        nonce.extend_from_slice(&stream_id.to_le_bytes());
        nonce.extend_from_slice(&sequence.to_le_bytes());
        
        aegis_q_encrypt(&stream_key, &nonce, data)
    }
    
    /// Decrypt stream data
    pub fn decrypt_stream(&self, stream_id: u32, ciphertext: &[u8], sequence: u64) -> Result<Vec<u8>, &'static str> {
        // Derive stream-specific key
        let mut stream_key = vec![0u8; 64];
        let hk = Hkdf::<Sha3_512>::new(Some(&self.session_nonce), &self.session_key);
        hk.expand(&stream_id.to_le_bytes(), &mut stream_key).unwrap();
        
        // Create nonce with stream ID and sequence
        let mut nonce = self.session_nonce.clone();
        nonce.extend_from_slice(&stream_id.to_le_bytes());
        nonce.extend_from_slice(&sequence.to_le_bytes());
        
        aegis_q_decrypt(&stream_key, &nonce, ciphertext)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_quic_session() {
        let session_key = b"session-key-123456789012345678901234567890";
        let session_nonce = b"session-nonce-123456";
        
        let session = QuicSession::new(session_key.to_vec(), session_nonce.to_vec());
        let stream_id = 1;
        
        let data = b"Hello, QUIC!";
        let encrypted = session.encrypt_stream(stream_id, data, 0);
        let decrypted = session.decrypt_stream(stream_id, &encrypted, 0).unwrap();
        
        assert_eq!(data, decrypted.as_slice());
    }
}

