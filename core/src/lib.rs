//! Aegis-Q Core Implementation
//! 
//! Four-layer round structure:
//! 1. LatticeMix - RLWE lattice operations
//! 2. CodeMix - Linear code operations  
//! 3. ZKMix - Zero-knowledge transformation
//! 4. MaskMix - Round random masking

pub mod state;
pub mod round;
pub mod encrypt;

pub use state::State;
pub use encrypt::{aegis_q_encrypt, aegis_q_decrypt, aegis_q_init};

