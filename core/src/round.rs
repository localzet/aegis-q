//! Aegis-Q Round Function
//! 
//! Implements the four-layer round transformation:
//! S_L' = LatticeMix(S_L)
//! S_C' = CodeMix(S_C)
//! S_Z' = ZKMix(S_Z, nonce)
//! S_M' = MaskMix(S_M, nonce)
//! S_next = concat(S_L', S_C', S_Z', S_M')

use crate::state::State;
use pq_primitives::lattice::{lattice_mix, derive_lattice_params};
use pq_primitives::eccodes::{code_mix, GeneratorMatrix, Permutation};
use pq_primitives::zk::zk_mix;
use sha3::{Shake256, digest::{Update, ExtendableOutput, XofReader}};

/// Number of rounds
pub const ROUNDS: usize = 10;

/// Apply MaskMix transformation
/// mask = SHAKE256(round_key || nonce || counter)
/// state_M' = state_M XOR mask
fn mask_mix(state: &mut Vec<u8>, round_key: &[u8], nonce: &[u8], counter: u64) {
    let mut hasher = Shake256::default();
    hasher.update(round_key);
    hasher.update(nonce);
    hasher.update(&counter.to_le_bytes());
    
    let mut reader = hasher.finalize_xof();
    let mut mask = vec![0u8; state.len()];
    reader.read(&mut mask);
    
    // XOR in constant time
    for i in 0..state.len() {
        state[i] ^= mask[i];
    }
}

/// Apply one round of Aegis-Q transformation
/// 
/// # Arguments
/// * `state` - Current state (modified in place)
/// * `round_key` - Round key for this round
/// * `nonce` - Nonce
/// * `counter` - Round counter
pub fn round(state: &mut State, round_key: &[u8], nonce: &[u8], counter: u64) {
    // Derive lattice parameters
    let (a, b) = derive_lattice_params(round_key, nonce);
    
    // Step 1: LatticeMix
    // S_L' = LatticeMix(S_L)
    let lattice_new = lattice_mix(&state.lattice, &a, &b);
    
    // Step 2: CodeMix
    // S_C' = CodeMix(S_C)
    let generator = GeneratorMatrix::from_key(round_key, nonce);
    let permutation = Permutation::from_key(round_key, nonce);
    let code_new = code_mix(&state.code, &generator, &permutation);
    
    // Step 3: ZKMix
    // S_Z' = ZKMix(S_Z, nonce)
    let zk_new = zk_mix(&state.zk, nonce);
    
    // Step 4: MaskMix
    // S_M' = MaskMix(S_M, nonce)
    let mut mask_new = state.mask.clone();
    mask_mix(&mut mask_new, round_key, nonce, counter);
    
    // Update state
    state.lattice = lattice_new;
    state.code = code_new;
    state.zk = zk_new;
    state.mask = mask_new;
}

/// Generate round keys from master key
pub fn derive_round_keys(key: &[u8], nonce: &[u8], num_rounds: usize) -> Vec<Vec<u8>> {
    use sha3::Sha3_512;
    use hkdf::Hkdf;
    
    let hk = Hkdf::<Sha3_512>::new(Some(nonce), key);
    let mut round_keys = Vec::new();
    
    for i in 0..num_rounds {
        let mut round_key = vec![0u8; 64];
        let label = format!("aegis-q-round-key-{}", i);
        hk.expand(label.as_bytes(), &mut round_key).unwrap();
        round_keys.push(round_key);
    }
    
    round_keys
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::State;
    
    #[test]
    fn test_round_basic() {
        let key = b"test-key-12345678";
        let nonce = b"test-nonce";
        
        let mut state = State::from_key(key, nonce);
        let round_key = b"round-key-123456";
        
        let state_before = state.clone();
        round(&mut state, round_key, nonce, 0);
        
        // State should change
        assert_ne!(state.lattice, state_before.lattice);
        assert_ne!(state.code, state_before.code);
        assert_ne!(state.zk, state_before.zk);
    }
    
    #[test]
    fn test_derive_round_keys() {
        let key = b"test-key-12345678";
        let nonce = b"test-nonce";
        
        let round_keys = derive_round_keys(key, nonce, 10);
        assert_eq!(round_keys.len(), 10);
        
        // All keys should be different
        for i in 0..round_keys.len() {
            for j in (i + 1)..round_keys.len() {
                assert_ne!(round_keys[i], round_keys[j]);
            }
        }
    }
}

