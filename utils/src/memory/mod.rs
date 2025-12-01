//! Memory management utilities
//! Secure memory allocation and zeroization

use std::ptr;

/// Secure memory arena for cryptographic operations
pub struct SecureArena {
    data: Vec<u8>,
}

impl SecureArena {
    /// Create a new secure arena with specified capacity
    pub fn new(capacity: usize) -> Self {
        Self {
            data: vec![0u8; capacity],
        }
    }

    /// Get mutable slice to arena memory
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.data
    }

    /// Get slice to arena memory
    pub fn as_slice(&self) -> &[u8] {
        &self.data
    }
}

impl Drop for SecureArena {
    fn drop(&mut self) {
        // Zeroize memory on drop
        unsafe {
            ptr::write_bytes(self.data.as_mut_ptr(), 0, self.data.len());
        }
    }
}

/// Zeroize a slice in constant time
pub fn zeroize(slice: &mut [u8]) {
    // Constant-time zeroization
    for byte in slice.iter_mut() {
        *byte = 0;
    }
    // Compiler barrier to prevent optimization
    unsafe {
        core::ptr::read_volatile(slice.as_ptr());
    }
}

/// Zeroize a vector
pub fn zeroize_vec(mut vec: Vec<u8>) {
    zeroize(&mut vec);
    vec.clear();
}

