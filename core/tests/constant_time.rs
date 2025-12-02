//! Constant-time operation tests

use aegis_q_core::aegis_q_encrypt;
use std::time::Instant;

#[test]
fn test_constant_time_encryption() {
    // Test that encryption time doesn't depend on plaintext content
    let key = b"test-key-123456789012345678901234567890";
    let nonce = b"test-nonce-123456";
    
    // Plaintext with all zeros
    let plaintext1 = vec![0u8; 1000];
    
    // Plaintext with all ones
    let plaintext2 = vec![0xFFu8; 1000];
    
    // Plaintext with random pattern
    let plaintext3: Vec<u8> = (0..1000).map(|i| (i % 256) as u8).collect();
    
    let times = vec![
        measure_time(|| { let _ = aegis_q_encrypt(key, nonce, &plaintext1); }),
        measure_time(|| { let _ = aegis_q_encrypt(key, nonce, &plaintext2); }),
        measure_time(|| { let _ = aegis_q_encrypt(key, nonce, &plaintext3); }),
    ];
    
    // Times should be similar (within 2x variance for measurement noise)
    let avg_time = times.iter().sum::<u64>() / times.len() as u64;
    for &time in &times {
        assert!((time as f64) / (avg_time as f64) < 2.0);
        assert!((avg_time as f64) / (time as f64) < 2.0);
    }
}

fn measure_time<F>(f: F) -> u64 
where
    F: FnOnce(),
{
    let start = Instant::now();
    f();
    start.elapsed().as_micros() as u64
}

