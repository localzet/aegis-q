//! Round function component tests

use pq_primitives::lattice::{lattice_mix, derive_lattice_params, N, Q};
use pq_primitives::eccodes::{code_mix, GeneratorMatrix, Permutation, CODE_N};
use pq_primitives::zk::zk_mix;

#[test]
fn test_lattice_mix_round() {
    let key = b"test-key-12345678";
    let nonce = b"test-nonce";
    
    let state: Vec<u32> = (0..N).map(|i| (i as u32) % Q as u32).collect();
    let (a, b) = derive_lattice_params(key, nonce);
    
    let result = lattice_mix(&state, &a, &b);
    assert_eq!(result.len(), N);
    assert_ne!(result, state); // Should transform
}

#[test]
fn test_code_mix_round() {
    let key = b"test-key-12345678";
    let nonce = b"test-nonce";
    
    let state: Vec<u32> = (0..CODE_N).map(|i| i as u32).collect();
    let generator = GeneratorMatrix::from_key(key, nonce);
    let permutation = Permutation::from_key(key, nonce);
    
    let result = code_mix(&state, &generator, &permutation);
    assert_eq!(result.len(), CODE_N);
    assert_ne!(result, state); // Should transform
}

#[test]
fn test_zk_mix_round() {
    let state = vec![0x42u8; 64];
    let nonce = b"test-nonce";
    
    let result = zk_mix(&state, nonce);
    assert_eq!(result.len(), 64);
    assert_ne!(result, state); // Should transform
}

