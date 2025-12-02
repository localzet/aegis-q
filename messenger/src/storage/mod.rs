//! Secure Local Storage
//! 
//! Encrypted storage for messenger data
//! Media, reactions, profile encryption

use aegis_q_core::{aegis_q_encrypt, aegis_q_decrypt};
use serde::{Serialize, Deserialize};
use sha3::{Digest, Sha3_256};
use utils::rng::random_bytes;

/// Storage key derivation
pub fn derive_storage_key(master_key: &[u8], purpose: &str) -> Vec<u8> {
    let mut hasher = Sha3_256::new();
    hasher.update(master_key);
    hasher.update(purpose.as_bytes());
    hasher.finalize().to_vec()
}

/// Encrypted storage entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageEntry {
    pub encrypted_data: Vec<u8>,
    pub nonce: Vec<u8>,
    pub purpose: String,
}

impl StorageEntry {
    /// Store data
    pub fn store(data: &[u8], master_key: &[u8], purpose: &str) -> Self {
        let storage_key = derive_storage_key(master_key, purpose);
        let nonce = random_bytes(16);
        
        let encrypted_data = aegis_q_encrypt(&storage_key, &nonce, data);
        
        Self {
            encrypted_data,
            nonce,
            purpose: purpose.to_string(),
        }
    }
    
    /// Retrieve data
    pub fn retrieve(&self, master_key: &[u8]) -> Result<Vec<u8>, &'static str> {
        let storage_key = derive_storage_key(master_key, &self.purpose);
        aegis_q_decrypt(&storage_key, &self.nonce, &self.encrypted_data)
    }
}

/// Media encryption
pub struct MediaStorage;

impl MediaStorage {
    /// Encrypt media file
    pub fn encrypt_media(media_data: &[u8], master_key: &[u8]) -> StorageEntry {
        StorageEntry::store(media_data, master_key, "media")
    }
    
    /// Decrypt media file
    pub fn decrypt_media(entry: &StorageEntry, master_key: &[u8]) -> Result<Vec<u8>, &'static str> {
        entry.retrieve(master_key)
    }
}

/// Profile encryption
pub struct ProfileStorage;

impl ProfileStorage {
    /// Encrypt profile data
    pub fn encrypt_profile(profile_data: &[u8], master_key: &[u8]) -> StorageEntry {
        StorageEntry::store(profile_data, master_key, "profile")
    }
    
    /// Decrypt profile data
    pub fn decrypt_profile(entry: &StorageEntry, master_key: &[u8]) -> Result<Vec<u8>, &'static str> {
        entry.retrieve(master_key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_storage_encrypt_decrypt() {
        let master_key = b"master-key-123456789012345678901234567890";
        let data = b"test-data";
        
        let entry = StorageEntry::store(data, master_key, "test");
        let retrieved = entry.retrieve(master_key).unwrap();
        
        assert_eq!(data, retrieved.as_slice());
    }
}

