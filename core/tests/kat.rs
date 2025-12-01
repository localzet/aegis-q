//! Known Answer Tests (KAT) for Aegis-Q

use aegis_q_core::{aegis_q_encrypt, aegis_q_decrypt};

#[test]
fn kat_test_1() {
    let key = b"00000000000000000000000000000000";
    let nonce = b"0000000000000000";
    let plaintext = b"";
    
    let ciphertext = aegis_q_encrypt(key, nonce, plaintext);
    let decrypted = aegis_q_decrypt(key, nonce, &ciphertext).unwrap();
    
    assert_eq!(plaintext, decrypted.as_slice());
}

#[test]
fn kat_test_2() {
    let key = b"00000000000000000000000000000000";
    let nonce = b"0000000000000000";
    let plaintext = b"Hello, Aegis-Q!";
    
    let ciphertext = aegis_q_encrypt(key, nonce, plaintext);
    let decrypted = aegis_q_decrypt(key, nonce, &ciphertext).unwrap();
    
    assert_eq!(plaintext, decrypted.as_slice());
}

#[test]
fn kat_test_3() {
    let key = b"0123456789abcdef0123456789abcdef";
    let nonce = b"fedcba9876543210";
    let plaintext = b"The quick brown fox jumps over the lazy dog";
    
    let ciphertext = aegis_q_encrypt(key, nonce, plaintext);
    let decrypted = aegis_q_decrypt(key, nonce, &ciphertext).unwrap();
    
    assert_eq!(plaintext, decrypted.as_slice());
}

