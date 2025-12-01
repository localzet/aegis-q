//! ZKMix - Zero-Knowledge transformation layer
//! 
//! Implements: ZKMix(x, r) = H(r || x) XOR x
//! Fully simulatable: Sim(r) = H(r || 0) XOR random()
//! Uses SHA3-512 or SHAKE-256, constant-time operations

use sha3::{Digest, Sha3_512, Shake256, digest::{Update, ExtendableOutput, XofReader}};

/// ZKMix state size (512 bits = 64 bytes)
pub const ZK_STATE_SIZE: usize = 64;

/// ZKMix state type
pub type ZKState = Vec<u8>;

/// Apply ZKMix transformation
/// ZKMix(x, r) = H(r || x) XOR x
/// 
/// Constant-time implementation
pub fn zk_mix(state: &ZKState, nonce: &[u8]) -> ZKState {
    assert_eq!(state.len(), ZK_STATE_SIZE);
    
    // H(r || x) where r is nonce, x is state
    let mut hasher = Sha3_512::new();
    hasher.update(nonce);
    hasher.update(state);
    let hash = hasher.finalize();
    
    // XOR with original state (constant-time)
    let mut result = vec![0u8; ZK_STATE_SIZE];
    for i in 0..ZK_STATE_SIZE {
        result[i] = state[i] ^ hash[i];
    }
    
    result
}

/// Simulator for ZKMix
/// Sim(r) = H(r || 0) XOR random()
/// 
/// Produces output that is computationally indistinguishable from real ZKMix
pub fn zk_simulate(nonce: &[u8], rng: &mut impl FnMut() -> u8) -> ZKState {
    // H(r || 0)
    let mut hasher = Sha3_512::new();
    hasher.update(nonce);
    hasher.update(&vec![0u8; ZK_STATE_SIZE]);
    let hash = hasher.finalize();
    
    // XOR with random
    let mut result = vec![0u8; ZK_STATE_SIZE];
    for i in 0..ZK_STATE_SIZE {
        result[i] = hash[i] ^ rng();
    }
    
    result
}

/// Alternative ZKMix using SHAKE-256 (extendable output)
pub fn zk_mix_shake(state: &ZKState, nonce: &[u8]) -> ZKState {
    assert_eq!(state.len(), ZK_STATE_SIZE);
    
    let mut hasher = Shake256::default();
    hasher.update(nonce);
    hasher.update(state);
    let mut reader = hasher.finalize_xof();
    
    let mut hash = vec![0u8; ZK_STATE_SIZE];
    reader.read(&mut hash);
    
    // XOR with original state
    let mut result = vec![0u8; ZK_STATE_SIZE];
    for i in 0..ZK_STATE_SIZE {
        result[i] = state[i] ^ hash[i];
    }
    
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_zk_mix_basic() {
        let state = vec![0x42u8; ZK_STATE_SIZE];
        let nonce = b"test-nonce-123";
        
        let result = zk_mix(&state, nonce);
        assert_eq!(result.len(), ZK_STATE_SIZE);
        assert_ne!(result, state); // Should be different
    }
    
    #[test]
    fn test_zk_mix_deterministic() {
        let state = vec![0x42u8; ZK_STATE_SIZE];
        let nonce = b"test-nonce-123";
        
        let result1 = zk_mix(&state, nonce);
        let result2 = zk_mix(&state, nonce);
        
        assert_eq!(result1, result2); // Should be deterministic
    }
    
    #[test]
    fn test_zk_simulate() {
        let nonce = b"test-nonce-123";
        let mut counter = 0u8;
        let mut rng = || {
            counter = counter.wrapping_add(1);
            counter
        };
        
        let result = zk_simulate(nonce, &mut rng);
        assert_eq!(result.len(), ZK_STATE_SIZE);
    }
}

