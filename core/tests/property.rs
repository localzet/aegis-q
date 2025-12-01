//! Property-based tests using proptest

use proptest::prelude::*;
use aegis_q_core::{aegis_q_encrypt, aegis_q_decrypt};

proptest! {
    #[test]
    fn encrypt_decrypt_roundtrip(
        key in prop::collection::vec(any::<u8>(), 32..64),
        nonce in prop::collection::vec(any::<u8>(), 16..32),
        plaintext in prop::collection::vec(any::<u8>(), 0..10000)
    ) {
        let ciphertext = aegis_q_encrypt(&key, &nonce, &plaintext);
        let decrypted = aegis_q_decrypt(&key, &nonce, &ciphertext).unwrap();
        prop_assert_eq!(plaintext, decrypted);
    }
    
    #[test]
    fn ciphertext_different_from_plaintext(
        key in prop::collection::vec(any::<u8>(), 32..64),
        nonce in prop::collection::vec(any::<u8>(), 16..32),
        plaintext in prop::collection::vec(any::<u8>(), 1..1000)
    ) {
        let ciphertext = aegis_q_encrypt(&key, &nonce, &plaintext);
        // Ciphertext should be different (accounting for tag)
        prop_assume!(plaintext.len() > 0);
        let encrypted_part = &ciphertext[..plaintext.len()];
        prop_assert_ne!(plaintext, encrypted_part);
    }
    
    #[test]
    fn wrong_key_fails(
        key1 in prop::collection::vec(any::<u8>(), 32..64),
        key2 in prop::collection::vec(any::<u8>(), 32..64),
        nonce in prop::collection::vec(any::<u8>(), 16..32),
        plaintext in prop::collection::vec(any::<u8>(), 1..100)
    ) {
        prop_assume!(key1 != key2);
        
        let ciphertext = aegis_q_encrypt(&key1, &nonce, &plaintext);
        let result = aegis_q_decrypt(&key2, &nonce, &ciphertext);
        prop_assert!(result.is_err());
    }
}

