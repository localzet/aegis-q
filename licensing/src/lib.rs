//! Licensing Protection Module
//! 
//! Key obfuscation, protected configuration, Aegis-Q envelope for license transmission
//! Binary protection (embeddable module)

use aegis_q_core::{aegis_q_encrypt, aegis_q_decrypt};
use sha3::{Digest, Sha3_512};
use serde::{Serialize, Deserialize};

/// License key structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct License {
    pub license_id: String,
    pub features: Vec<String>,
    pub expiry: u64,
    pub signature: Vec<u8>,
}

impl License {
    /// Create new license
    pub fn new(license_id: String, features: Vec<String>, expiry: u64) -> Self {
        Self {
            license_id,
            features,
            expiry,
            signature: Vec::new(),
        }
    }
    
    /// Sign license
    pub fn sign(&mut self, signing_key: &[u8]) {
        let mut hasher = Sha3_512::new();
        hasher.update(&self.license_id.as_bytes());
        for feature in &self.features {
            hasher.update(feature.as_bytes());
        }
        hasher.update(&self.expiry.to_le_bytes());
        self.signature = hasher.finalize().to_vec();
    }
    
    /// Verify license signature
    pub fn verify(&self, signing_key: &[u8]) -> bool {
        let mut hasher = Sha3_512::new();
        hasher.update(&self.license_id.as_bytes());
        for feature in &self.features {
            hasher.update(feature.as_bytes());
        }
        hasher.update(&self.expiry.to_le_bytes());
        let computed = hasher.finalize();
        
        // Constant-time comparison
        let mut result = 0u8;
        for (a, b) in computed.iter().zip(self.signature.iter()) {
            result |= a ^ b;
        }
        result == 0
    }
}

/// Obfuscated key storage
pub struct ObfuscatedKey {
    encrypted_key: Vec<u8>,
    obfuscation_seed: Vec<u8>,
}

impl ObfuscatedKey {
    /// Create obfuscated key
    pub fn new(key: &[u8], obfuscation_seed: &[u8]) -> Self {
        // Encrypt key using Aegis-Q
        let nonce = vec![0u8; 16];
        let encrypted_key = aegis_q_encrypt(obfuscation_seed, &nonce, key);
        
        Self {
            encrypted_key,
            obfuscation_seed: obfuscation_seed.to_vec(),
        }
    }
    
    /// Retrieve deobfuscated key
    pub fn deobfuscate(&self) -> Result<Vec<u8>, &'static str> {
        let nonce = vec![0u8; 16];
        aegis_q_decrypt(&self.obfuscation_seed, &nonce, &self.encrypted_key)
    }
}

/// Protected configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtectedConfig {
    encrypted_config: Vec<u8>,
    config_nonce: Vec<u8>,
}

impl ProtectedConfig {
    /// Create protected configuration
    pub fn new(config_data: &[u8], config_key: &[u8]) -> Self {
        let config_nonce = vec![0u8; 16];
        let encrypted_config = aegis_q_encrypt(config_key, &config_nonce, config_data);
        
        Self {
            encrypted_config,
            config_nonce,
        }
    }
    
    /// Retrieve configuration
    pub fn retrieve(&self, config_key: &[u8]) -> Result<Vec<u8>, &'static str> {
        aegis_q_decrypt(config_key, &self.config_nonce, &self.encrypted_config)
    }
}

/// Aegis-Q envelope for license transmission
pub struct LicenseEnvelope {
    encrypted_license: Vec<u8>,
    envelope_nonce: Vec<u8>,
}

impl LicenseEnvelope {
    /// Create license envelope
    pub fn create(license: &License, envelope_key: &[u8]) -> Result<Self, &'static str> {
        let license_bytes = serde_json::to_vec(license)
            .map_err(|_| "Serialization failed")?;
        
        let envelope_nonce = vec![0u8; 16];
        let encrypted_license = aegis_q_encrypt(envelope_key, &envelope_nonce, &license_bytes);
        
        Ok(Self {
            encrypted_license,
            envelope_nonce,
        })
    }
    
    /// Extract license from envelope
    pub fn extract(&self, envelope_key: &[u8]) -> Result<License, &'static str> {
        let license_bytes = aegis_q_decrypt(envelope_key, &self.envelope_nonce, &self.encrypted_license)?;
        serde_json::from_slice(&license_bytes)
            .map_err(|_| "Deserialization failed")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_license_sign_verify() {
        let signing_key = b"signing-key";
        let mut license = License::new(
            "test-license".to_string(),
            vec!["feature1".to_string(), "feature2".to_string()],
            1234567890,
        );
        
        license.sign(signing_key);
        assert!(license.verify(signing_key));
    }
    
    #[test]
    fn test_obfuscated_key() {
        let key = b"secret-key-123456789012345678901234567890";
        let obf_seed = b"obfuscation-seed-123456789012345678901234567890";
        
        let obf_key = ObfuscatedKey::new(key, obf_seed);
        let deobf = obf_key.deobfuscate().unwrap();
        
        assert_eq!(key, deobf.as_slice());
    }
    
    #[test]
    fn test_license_envelope() {
        let envelope_key = b"envelope-key-123456789012345678901234567890";
        let mut license = License::new(
            "test-license".to_string(),
            vec!["feature1".to_string()],
            1234567890,
        );
        license.sign(b"signing-key");
        
        let envelope = LicenseEnvelope::create(&license, envelope_key).unwrap();
        let extracted = envelope.extract(envelope_key).unwrap();
        
        assert_eq!(license.license_id, extracted.license_id);
    }
}

