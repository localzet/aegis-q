//! Aegis-Q State structure
//! 
//! State consists of four components:
//! - lattice: LatticeMix state (4096 u32 values)
//! - code: CodeMix state (4096 u32 values)
//! - zk: ZKMix state (64 bytes)
//! - mask: MaskMix state (variable size, typically 64 bytes)

use pq_primitives::lattice::{LatticeState, N as LATTICE_N};
use pq_primitives::eccodes::{CodeState, CODE_N};
use pq_primitives::zk::ZKState;

/// Aegis-Q State structure
#[derive(Clone)]
pub struct State {
    /// LatticeMix state: polynomial in R_q
    pub lattice: LatticeState,
    /// CodeMix state: code vector
    pub code: CodeState,
    /// ZKMix state: zero-knowledge layer
    pub zk: ZKState,
    /// MaskMix state: masking layer
    pub mask: Vec<u8>,
}

impl State {
    /// Create new state from components
    pub fn new(lattice: LatticeState, code: CodeState, zk: ZKState, mask: Vec<u8>) -> Self {
        assert_eq!(lattice.len(), LATTICE_N);
        assert_eq!(code.len(), CODE_N);
        assert_eq!(zk.len(), pq_primitives::zk::ZK_STATE_SIZE);
        
        Self {
            lattice,
            code,
            zk,
            mask,
        }
    }
    
    /// Initialize state from key and nonce
    pub fn from_key(key: &[u8], nonce: &[u8]) -> Self {
        use sha3::{Shake256, digest::{Update, ExtendableOutput, XofReader}};

        // Helper to expand with SHAKE256 using domain separation
        fn shake_expand(label: &[u8], key: &[u8], nonce: &[u8], out: &mut [u8]) {
            let mut hasher = Shake256::default();
            hasher.update(b"aegis-q-state");
            hasher.update(label);
            hasher.update(key);
            hasher.update(nonce);
            let mut reader = hasher.finalize_xof();
            reader.read(out);
        }

        // Derive lattice state
        let mut lattice_bytes = vec![0u8; LATTICE_N * 4];
        shake_expand(b"lattice", key, nonce, &mut lattice_bytes);
        let lattice: LatticeState = lattice_bytes
            .chunks_exact(4)
            .map(|chunk| u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]))
            .collect();
        
        // Derive code state
        let mut code_bytes = vec![0u8; CODE_N * 4];
        shake_expand(b"code", key, nonce, &mut code_bytes);
        let code: CodeState = code_bytes
            .chunks_exact(4)
            .map(|chunk| u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]))
            .collect();
        
        // Derive ZK state
        let mut zk_bytes = vec![0u8; pq_primitives::zk::ZK_STATE_SIZE];
        shake_expand(b"zk", key, nonce, &mut zk_bytes);
        let zk = zk_bytes;
        
        // Derive mask state
        let mut mask_bytes = vec![0u8; 64];
        shake_expand(b"mask", key, nonce, &mut mask_bytes);
        let mask = mask_bytes;
        
        Self {
            lattice,
            code,
            zk,
            mask,
        }
    }
    
    /// Concatenate state components into byte vector
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut result = Vec::new();
        
        // Lattice (4096 * 4 = 16384 bytes)
        for &val in &self.lattice {
            result.extend_from_slice(&val.to_le_bytes());
        }
        
        // Code (4096 * 4 = 16384 bytes)
        for &val in &self.code {
            result.extend_from_slice(&val.to_le_bytes());
        }
        
        // ZK (64 bytes)
        result.extend_from_slice(&self.zk);
        
        // Mask (variable)
        result.extend_from_slice(&self.mask);
        
        result
    }
    
    /// Reconstruct state from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, &'static str> {
        const LATTICE_BYTES: usize = LATTICE_N * 4;
        const CODE_BYTES: usize = CODE_N * 4;
        const ZK_BYTES: usize = pq_primitives::zk::ZK_STATE_SIZE;
        const MIN_SIZE: usize = LATTICE_BYTES + CODE_BYTES + ZK_BYTES;
        
        if bytes.len() < MIN_SIZE {
            return Err("Invalid state size");
        }
        
        // Parse lattice
        let lattice: LatticeState = bytes[0..LATTICE_BYTES]
            .chunks_exact(4)
            .map(|chunk| u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]))
            .collect();
        
        // Parse code
        let code: CodeState = bytes[LATTICE_BYTES..LATTICE_BYTES + CODE_BYTES]
            .chunks_exact(4)
            .map(|chunk| u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]))
            .collect();
        
        // Parse ZK
        let zk = bytes[LATTICE_BYTES + CODE_BYTES..LATTICE_BYTES + CODE_BYTES + ZK_BYTES].to_vec();
        
        // Parse mask (remaining bytes)
        let mask = bytes[LATTICE_BYTES + CODE_BYTES + ZK_BYTES..].to_vec();
        
        Ok(Self {
            lattice,
            code,
            zk,
            mask,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_state_serialization() {
        let key = b"test-key-12345678";
        let nonce = b"test-nonce";
        
        let state1 = State::from_key(key, nonce);
        let bytes = state1.to_bytes();
        let state2 = State::from_bytes(&bytes).unwrap();
        
        assert_eq!(state1.lattice, state2.lattice);
        assert_eq!(state1.code, state2.code);
        assert_eq!(state1.zk, state2.zk);
        assert_eq!(state1.mask, state2.mask);
    }
}

