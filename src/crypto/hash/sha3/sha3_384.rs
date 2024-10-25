//! SHA3-384 implementation
//! SHA3-384 is part of the SHA-3 family of cryptographic hash functions,
//! standardized by NIST in FIPS 202.

use super::sha3_util::{RC, keccak_f1600_round};
#[allow(unused_imports)]
pub use crate::utils::x2x::ToHexExt;

/// Rate in bytes (832 bits) for SHA3-384
/// Rate represents the portion of the state that is used for absorbing input
#[allow(unused)]
const RATE: usize = 104;

/// Capacity in bytes (768 bits) for SHA3-384
/// Capacity represents the security parameter of the hash function
/// Rate + Capacity = 1600 bits (200 bytes), which is the state size of Keccak-f[1600]
#[allow(unused)]
const CAPACITY: usize = 96;

/// Output size in bytes (384 bits) for SHA3-384
#[allow(unused)]
const HASH_SIZE: usize = 48;

/// SHA3-384 hasher implementation
/// 
/// This struct maintains the internal state of the SHA3-384 hash computation.
/// The state consists of a 5x5 array of 64-bit words (1600 bits total),
/// a buffer for incomplete blocks, and the current buffer length.
pub struct Sha3_384 {
    /// Main state array (5x5 matrix of 64-bit words)
    state: [[u64; 5]; 5],
    /// Buffer for incomplete blocks
    buffer: [u8; RATE],
    /// Current number of bytes in the buffer
    buffer_len: usize,
}

impl Sha3_384 {
    /// Creates a new SHA3-384 hasher instance with initialized state
    pub fn new() -> Self {
        Sha3_384 {
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
    /// * A 48-byte array containing the SHA3-384 hash value
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

/// Convenience function to compute the SHA3-384 hash of input data
/// 
/// # Arguments
/// 
/// * `data` - Input data to be hashed
/// 
/// # Returns
/// 
/// * A 48-byte array containing the SHA3-384 hash value
/// 
/// # Example
/// 
/// ```
/// use cryptos::hash::sha3::sha3_384;
/// 
/// let data = b"Hello, world!";
/// let hash = sha3_384(data);
/// ```
pub fn sha3_384(data: &[u8]) -> [u8; HASH_SIZE] {
    let mut hasher = Sha3_384::new();
    hasher.update(data);
    hasher.finalize()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::check::compare_check;

    #[test]
    fn test_sha3_384() {
        let test_cases = vec![
            (
                "".as_bytes().to_vec(),
                "0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004".to_string()
            ),
            (
                "Get busy living, or get busy dying. That's goddamn right.".as_bytes().to_vec(),
                "33b0843c2ba6e530880c8c410e442dfdccb1f9bb283cd5641094b47ac10b73a1479ef4db41ded5a245b54afa0e91d419".to_string()
            ),
            (
                "I guess it comes down to a simple choice, really. Get busy living or get busy dying.".as_bytes().to_vec(),
                "1ff3cf5a8d2b5765c02a6d7331e963e070fe262d9924c61bc2ef338f99fc52b607f96e88d01715db4c864c153e2a6ac6".to_string()
            ),
        ];

        let sha3_384_test = |input: &Vec<u8>| {
            let result = sha3_384(input);
            result.to_hex(false)
        };

        assert!(compare_check(test_cases, "SHA3-384", sha3_384_test));
    }
}

