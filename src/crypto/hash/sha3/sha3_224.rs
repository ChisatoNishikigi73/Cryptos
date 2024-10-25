//! SHA3-224 implementation
//! SHA3-224 is part of the SHA-3 family of cryptographic hash functions,
//! standardized by NIST in FIPS 202.

use super::sha3_util::{RC, keccak_f1600_round};
#[allow(unused_imports)]
pub use crate::utils::x2x::ToHexExt;

/// Rate in bytes (1152 bits) for SHA3-224
/// Rate represents the portion of the state that is used for absorbing input
#[allow(unused)]
const RATE: usize = 144;

/// Capacity in bytes (448 bits) for SHA3-224
/// Capacity represents the security parameter of the hash function
/// Rate + Capacity = 1600 bits (200 bytes), which is the state size of Keccak-f[1600]
#[allow(unused)]
const CAPACITY: usize = 56;

/// Output size in bytes (224 bits) for SHA3-224
#[allow(unused)]
const HASH_SIZE: usize = 28;

/// SHA3-224 hasher implementation
/// 
/// This struct maintains the internal state of the SHA3-224 hash computation.
/// The state consists of a 5x5 array of 64-bit words (1600 bits total),
/// a buffer for incomplete blocks, and the current buffer length.
pub struct Sha3_224 {
    /// Main state array (5x5 matrix of 64-bit words)
    state: [[u64; 5]; 5],
    /// Buffer for incomplete blocks
    buffer: [u8; RATE],
    /// Current number of bytes in the buffer
    buffer_len: usize,
}

impl Sha3_224 {
    /// Creates a new SHA3-224 hasher instance with initialized state
    pub fn new() -> Self {
        Sha3_224 {
            state: [[0u64; 5]; 5],
            buffer: [0; RATE],
            buffer_len: 0,
        }
    }

    /// Updates the hash with new input data
    /// 
    /// # Arguments
    /// 
    /// * `data` - Input data to be hashed
    pub fn update(&mut self, data: &[u8]) {
        let mut data_index = 0;

        if self.buffer_len > 0 {
            let to_copy = (RATE - self.buffer_len).min(data.len());
            self.buffer[self.buffer_len..self.buffer_len + to_copy].copy_from_slice(&data[..to_copy]);
            self.buffer_len += to_copy;

            if self.buffer_len == RATE {
                let buffer = self.buffer;
                self.process_block(&buffer);
                self.buffer_len = 0;
            }
        }

        while data_index + RATE <= data.len() {
            self.process_block(&data[data_index..data_index + RATE]);
            data_index += RATE;
        }

        if data_index < data.len() {
            let remaining = data.len() - data_index;
            self.buffer[..remaining].copy_from_slice(&data[data_index..]);
            self.buffer_len = remaining;
        }
    }

    /// Finalizes the hash computation and returns the hash value
    /// 
    /// This method applies the SHA3 padding rule (append 0b01 and fill with zeros, then 1)
    /// and performs the final squeezing operation.
    /// 
    /// # Returns
    /// 
    /// * A 28-byte array containing the SHA3-224 hash value
    pub fn finalize(&mut self) -> [u8; HASH_SIZE] {
        // SHA3 padding: append 0b01 and fill with zeros, then 1
        self.buffer[self.buffer_len] = 0x06;
        self.buffer[RATE - 1] |= 0x80;
        
        let buffer = self.buffer;
        self.process_block(&buffer);

        let mut result = [0u8; HASH_SIZE];
        let mut offset = 0;
        'outer: for y in 0..5 {
            for x in 0..5 {
                if offset >= HASH_SIZE {
                    break 'outer;
                }
                let bytes = self.state[x][y].to_le_bytes();
                let remaining = HASH_SIZE - offset;
                let to_copy = remaining.min(8);
                result[offset..offset + to_copy].copy_from_slice(&bytes[..to_copy]);
                offset += to_copy;
            }
        }
        result
    }

    /// Processes a single block of data using the Keccak-f[1600] permutation
    /// 
    /// # Arguments
    /// 
    /// * `block` - A block of data of size RATE bytes
    fn process_block(&mut self, block: &[u8]) {
        // XOR input with state
        for (i, chunk) in block.chunks_exact(8).enumerate() {
            let x = i % 5;
            let y = i / 5;
            let mut bytes = [0u8; 8];
            bytes.copy_from_slice(chunk);
            self.state[x][y] ^= u64::from_le_bytes(bytes);
        }

        // Apply Keccak-f[1600]
        for round in 0..24 {
            keccak_f1600_round(&mut self.state, RC[round]);
        }
    }
}

/// Convenience function to compute the SHA3-224 hash of input data
/// 
/// # Arguments
/// 
/// * `data` - Input data to be hashed
/// 
/// # Returns
/// 
/// * A 28-byte array containing the SHA3-224 hash value
/// 
/// # Example
/// 
/// ```
/// use cryptos::hash::sha3::sha3_224;
/// 
/// let data = b"Hello, world!";
/// let hash = sha3_224(data);
/// ```
pub fn sha3_224(data: &[u8]) -> [u8; HASH_SIZE] {
    let mut hasher = Sha3_224::new();
    hasher.update(data);
    hasher.finalize()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::check::compare_check;

    #[test]
    fn test_sha3_224() {
        let test_cases = vec![
            (
                "".as_bytes().to_vec(),
                "6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7".to_string()
            ),
            (
                "Hope is a good thing and maybe the best of things. And no good thing ever dies. ".as_bytes().to_vec(),
                "e8758136b54af7359a513ab45ac330d7244829d4f80de5634ff05f45".to_string()
            ),
            (
                "Life was like a box of chocolates, you never know what you're gonna get.".as_bytes().to_vec(),
                "c559d20f93dae72aac580c3581c060aa13dfdcc9ae8bc352b6fa85b9".to_string()
            ),
        ];

        let sha3_224_test = |input: &Vec<u8>| {
            let result = sha3_224(input);
            result.to_hex(false)
        };

        assert!(compare_check(test_cases, "SHA3-224", sha3_224_test));
    }
}
