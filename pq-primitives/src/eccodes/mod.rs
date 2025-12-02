//! CodeMix - Linear code operations
//! 
//! Implements: state_C' = P * G * state_C
//! Where G is a generator matrix (4096×4096) and P is a secret permutation
//! Strictly linear operations, O(n²) complexity

use sha3::{Digest, Sha3_512};
use utils::kdf::kdf_shake256;

/// Code dimension
#[cfg(feature = "small_params")]
pub const CODE_N: usize = 256;
#[cfg(not(feature = "small_params"))]
pub const CODE_N: usize = 4096;

/// Generator matrix type (sparse representation for efficiency)
pub struct GeneratorMatrix {
    /// Sparse representation: (row, col, value) tuples
    entries: Vec<(usize, usize, u32)>,
    n: usize,
}

impl GeneratorMatrix {
    /// Generate generator matrix from key using HKDF
    pub fn from_key(key: &[u8], nonce: &[u8]) -> Self {
        // Derive matrix entries deterministically
        let mut entries = Vec::new();
        
        // Generate sparse matrix (density ~0.1 for efficiency)
        for row in 0..CODE_N {
            for col in 0..CODE_N {
                // Sparse: only include ~10% of entries
                let seed = kdf_shake256(
                    b"aegis-q-codemix-matrix",
                    key,
                    &format!("{}-{}", row, col).into_bytes(),
                    64,
                );

                let hash = Sha3_512::digest(seed);
                let should_include = hash[0] < 25; // ~10% density
                
                if should_include {
                    let value = u32::from_le_bytes([
                        hash[1], hash[2], hash[3], hash[4]
                    ]);
                    entries.push((row, col, value));
                }
            }
        }
        
        Self {
            entries,
            n: CODE_N,
        }
    }
    
    /// Matrix-vector multiplication: G * state
    pub fn multiply(&self, state: &[u32]) -> Vec<u32> {
        assert_eq!(state.len(), CODE_N);
        
        let mut result = vec![0u32; CODE_N];
        
        // Sparse matrix multiplication
        for (row, col, value) in &self.entries {
            result[*row] = result[*row].wrapping_add(
                state[*col].wrapping_mul(*value)
            );
        }
        
        result
    }
}

/// Secret permutation
pub struct Permutation {
    /// Permutation array: P[i] = j means position i maps to position j
    perm: Vec<usize>,
    /// Inverse permutation
    inv_perm: Vec<usize>,
}

impl Permutation {
    /// Generate permutation from key using HKDF
    pub fn from_key(key: &[u8], nonce: &[u8]) -> Self {
        // Generate permutation using Fisher-Yates shuffle with deterministic RNG
        let mut perm: Vec<usize> = (0..CODE_N).collect();
        
        // Deterministic shuffle based on key
        for i in (1..CODE_N).rev() {
            let seed = kdf_shake256(
                b"aegis-q-codemix-perm",
                key,
                &format!("{}", i).into_bytes(),
                64,
            );
            let hash = Sha3_512::digest(seed);
            let j = u64::from_le_bytes([
                hash[0], hash[1], hash[2], hash[3],
                hash[4], hash[5], hash[6], hash[7],
            ]) as usize % (i + 1);
            
            perm.swap(i, j);
        }
        
        // Compute inverse permutation
        let mut inv_perm = vec![0; CODE_N];
        for (i, &p) in perm.iter().enumerate() {
            inv_perm[p] = i;
        }
        
        Self { perm, inv_perm }
    }
    
    /// Apply permutation: P * state
    pub fn apply(&self, state: &[u32]) -> Vec<u32> {
        assert_eq!(state.len(), CODE_N);
        
        let mut result = vec![0u32; CODE_N];
        for i in 0..CODE_N {
            result[i] = state[self.perm[i]];
        }
        result
    }
    
    /// Apply inverse permutation: P^(-1) * state
    pub fn apply_inverse(&self, state: &[u32]) -> Vec<u32> {
        assert_eq!(state.len(), CODE_N);
        
        let mut result = vec![0u32; CODE_N];
        for i in 0..CODE_N {
            result[self.inv_perm[i]] = state[i];
        }
        result
    }
}

/// CodeMix state
pub type CodeState = Vec<u32>;

/// Apply CodeMix transformation
/// state_C' = P * G * state_C
pub fn code_mix(
    state: &CodeState,
    generator: &GeneratorMatrix,
    permutation: &Permutation,
) -> CodeState {
    assert_eq!(state.len(), CODE_N);
    
    // Step 1: G * state
    let g_state = generator.multiply(state);
    
    // Step 2: P * (G * state)
    permutation.apply(&g_state)
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    #[cfg_attr(feature = "small_params", ignore)]
    fn test_code_mix_basic() {
        let key = b"test-key-12345678";
        let nonce = b"test-nonce";
        
        let state: CodeState = (0..CODE_N).map(|i| i as u32).collect();
        let generator = GeneratorMatrix::from_key(key, nonce);
        let permutation = Permutation::from_key(key, nonce);
        
        let result = code_mix(&state, &generator, &permutation);
        assert_eq!(result.len(), CODE_N);
    }
    
    #[test]
    #[cfg_attr(feature = "small_params", ignore)]
    fn test_permutation_inverse() {
        let key = b"test-key-12345678";
        let nonce = b"test-nonce";
        
        let perm = Permutation::from_key(key, nonce);
        let state: CodeState = (0..CODE_N).map(|i| i as u32).collect();
        
        let permuted = perm.apply(&state);
        let restored = perm.apply_inverse(&permuted);
        
        assert_eq!(state, restored);
    }
}

