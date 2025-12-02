//! Differential timing tests for pq-primitives
//!
//! These tests are intentionally marked as `ignored` because they are
//! relatively heavy even with `small_params`. Run them manually, e.g.:
//!
//! `cargo test -p pq-primitives --tests --features small_params -- --ignored`

use std::time::Instant;

use pq_primitives::lattice::{lattice_mix, derive_lattice_params, N as LATTICE_N};
use pq_primitives::eccodes::{code_mix, GeneratorMatrix, Permutation, CODE_N};
use pq_primitives::zk::{zk_mix, ZK_STATE_SIZE};

#[test]
#[ignore]
fn timing_lattice_mix_constant_time_like() {
    let key = b"timing-key-lattice";
    let nonce = b"timing-nonce";

    // Different contents, same size
    let state_zero: Vec<u32> = vec![0; LATTICE_N];
    let state_ones: Vec<u32> = vec![u32::MAX; LATTICE_N];
    let state_pattern: Vec<u32> = (0..LATTICE_N as u32).collect();

    let (a, b) = derive_lattice_params(key, nonce);

    let times = vec![
        measure(|| lattice_mix(&state_zero, &a, &b)),
        measure(|| lattice_mix(&state_ones, &a, &b)),
        measure(|| lattice_mix(&state_pattern, &a, &b)),
    ];

    assert_timing_within_factor(&times, 2.0);
}

#[test]
#[ignore]
fn timing_codemix_constant_time_like() {
    let key = b"timing-key-codemix";
    let nonce = b"timing-nonce";

    let state_zero: Vec<u32> = vec![0; CODE_N];
    let state_ones: Vec<u32> = vec![u32::MAX; CODE_N];
    let state_pattern: Vec<u32> = (0..CODE_N as u32).collect();

    let generator = GeneratorMatrix::from_key(key, nonce);
    let permutation = Permutation::from_key(key, nonce);

    let times = vec![
        measure(|| code_mix(&state_zero, &generator, &permutation)),
        measure(|| code_mix(&state_ones, &generator, &permutation)),
        measure(|| code_mix(&state_pattern, &generator, &permutation)),
    ];

    assert_timing_within_factor(&times, 2.0);
}

#[test]
#[ignore]
fn timing_zkmix_constant_time_like() {
    let nonce = b"timing-nonce";

    let state_zero: Vec<u8> = vec![0; ZK_STATE_SIZE];
    let state_ones: Vec<u8> = vec![0xFF; ZK_STATE_SIZE];
    let state_pattern: Vec<u8> = (0..ZK_STATE_SIZE as u8).collect();

    let times = vec![
        measure(|| zk_mix(&state_zero, nonce)),
        measure(|| zk_mix(&state_ones, nonce)),
        measure(|| zk_mix(&state_pattern, nonce)),
    ];

    assert_timing_within_factor(&times, 2.0);
}

fn measure<F, R>(f: F) -> u64
where
    F: FnOnce() -> R,
{
    let start = Instant::now();
    let _ = f();
    start.elapsed().as_micros() as u64
}

fn assert_timing_within_factor(samples: &[u64], factor: f64) {
    assert!(!samples.is_empty());
    let sum: u64 = samples.iter().copied().sum();
    let avg = sum as f64 / samples.len() as f64;

    for &t in samples {
        let t = t as f64;
        assert!(t / avg < factor, "timing deviation too large: {} vs avg {}", t, avg);
        assert!(avg / t < factor, "timing deviation too large: {} vs avg {}", t, avg);
    }
}


