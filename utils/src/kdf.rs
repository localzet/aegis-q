//! Aegis-Q KDF helpers with strict domain separation
//!
//! All key derivation in the system should go through these helpers.

use sha3::{Shake256, digest::{Update, ExtendableOutput, XofReader}};

/// Derive `out_len` bytes from `key_material` and optional `info`, under a domain label.
///
/// K_out = SHAKE256("aegis-q-kdf" || domain || key_material || info)
pub fn kdf_shake256(domain: &[u8], key_material: &[u8], info: &[u8], out_len: usize) -> Vec<u8> {
    let mut hasher = Shake256::default();
    hasher.update(b"aegis-q-kdf");
    hasher.update(domain);
    hasher.update(key_material);
    hasher.update(info);
    let mut reader = hasher.finalize_xof();

    let mut out = vec![0u8; out_len];
    reader.read(&mut out);
    out
}

/// Fill an existing buffer with KDF output.
pub fn kdf_shake256_fill(domain: &[u8], key_material: &[u8], info: &[u8], out: &mut [u8]) {
    let mut hasher = Shake256::default();
    hasher.update(b"aegis-q-kdf");
    hasher.update(domain);
    hasher.update(key_material);
    hasher.update(info);
    let mut reader = hasher.finalize_xof();
    reader.read(out);
}


