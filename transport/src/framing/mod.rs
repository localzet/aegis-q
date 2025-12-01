//! Aegis-Q Frame Format
//! 
//! Frame structure for Aegis-Q transport layer
//! Replaces TLS framing

use aegis_q_core::{aegis_q_encrypt, aegis_q_decrypt};
use serde::{Serialize, Deserialize};

/// Frame header size
pub const FRAME_HEADER_SIZE: usize = 16;

/// Frame type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameType {
    Handshake = 0x01,
    Data = 0x02,
    Close = 0x03,
    Heartbeat = 0x04,
}

impl From<u8> for FrameType {
    fn from(value: u8) -> Self {
        match value {
            0x01 => FrameType::Handshake,
            0x02 => FrameType::Data,
            0x03 => FrameType::Close,
            0x04 => FrameType::Heartbeat,
            _ => FrameType::Data, // Default
        }
    }
}

/// Aegis-Q Frame
#[derive(Debug, Clone)]
pub struct Frame {
    pub frame_type: FrameType,
    pub payload: Vec<u8>,
    pub sequence: u64,
}

impl Frame {
    /// Create new frame
    pub fn new(frame_type: FrameType, payload: Vec<u8>, sequence: u64) -> Self {
        Self {
            frame_type,
            payload,
            sequence,
        }
    }
    
    /// Encode frame to bytes
    pub fn encode(&self) -> Vec<u8> {
        let mut result = Vec::new();
        
        // Frame type (1 byte)
        result.push(self.frame_type as u8);
        
        // Sequence number (8 bytes)
        result.extend_from_slice(&self.sequence.to_le_bytes());
        
        // Payload length (4 bytes)
        result.extend_from_slice(&(self.payload.len() as u32).to_le_bytes());
        
        // Reserved (3 bytes)
        result.extend_from_slice(&[0u8; 3]);
        
        // Payload
        result.extend_from_slice(&self.payload);
        
        result
    }
    
    /// Decode frame from bytes
    pub fn decode(data: &[u8]) -> Result<Self, &'static str> {
        if data.len() < FRAME_HEADER_SIZE {
            return Err("Frame too short");
        }
        
        let frame_type = FrameType::from(data[0]);
        let sequence = u64::from_le_bytes([
            data[1], data[2], data[3], data[4],
            data[5], data[6], data[7], data[8],
        ]);
        let payload_len = u32::from_le_bytes([
            data[9], data[10], data[11], data[12],
        ]) as usize;
        
        if data.len() < FRAME_HEADER_SIZE + payload_len {
            return Err("Incomplete frame");
        }
        
        let payload = data[FRAME_HEADER_SIZE..FRAME_HEADER_SIZE + payload_len].to_vec();
        
        Ok(Self {
            frame_type,
            payload,
            sequence,
        })
    }
    
    /// Encrypt frame payload
    pub fn encrypt(&mut self, key: &[u8], nonce: &[u8]) {
        let nonce_with_seq = {
            let mut n = nonce.to_vec();
            n.extend_from_slice(&self.sequence.to_le_bytes());
            n
        };
        
        self.payload = aegis_q_encrypt(key, &nonce_with_seq, &self.payload);
    }
    
    /// Decrypt frame payload
    pub fn decrypt(&mut self, key: &[u8], nonce: &[u8]) -> Result<(), &'static str> {
        let nonce_with_seq = {
            let mut n = nonce.to_vec();
            n.extend_from_slice(&self.sequence.to_le_bytes());
            n
        };
        
        self.payload = aegis_q_decrypt(key, &nonce_with_seq, &self.payload)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_frame_encode_decode() {
        let frame = Frame::new(
            FrameType::Data,
            b"Hello, World!".to_vec(),
            12345,
        );
        
        let encoded = frame.encode();
        let decoded = Frame::decode(&encoded).unwrap();
        
        assert_eq!(frame.frame_type, decoded.frame_type);
        assert_eq!(frame.payload, decoded.payload);
        assert_eq!(frame.sequence, decoded.sequence);
    }
}

