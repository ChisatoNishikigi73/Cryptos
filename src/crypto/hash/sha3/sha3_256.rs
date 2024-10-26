//! SHA3-256 implementation
//! SHA3-256 is part of the SHA-3 family of cryptographic hash functions,
//! standardized by NIST in FIPS 202.

use super::sha3_util::{RC, keccak_f1600_round};

/// Rate in bytes (1088 bits) for SHA3-256
/// Rate represents the portion of the state that is used for absorbing input
#[allow(unused)]
const RATE: usize = 136;

/// Capacity in bytes (512 bits) for SHA3-256
/// Capacity represents the security parameter of the hash function
/// Rate + Capacity = 1600 bits (200 bytes), which is the state size of Keccak-f[1600]
#[allow(unused)]
const CAPACITY: usize = 64;

/// Output size in bytes (256 bits) for SHA3-256
#[allow(unused)]
const HASH_SIZE: usize = 32;

/// SHA3-256 hasher implementation
/// 
/// This struct maintains the internal state of the SHA3-256 hash computation.
/// The state consists of a 5x5 array of 64-bit words (1600 bits total),
/// a buffer for incomplete blocks, and the current buffer length.
pub struct Sha3_256 {
    /// Main state array (5x5 matrix of 64-bit words)
    state: [[u64; 5]; 5],
    /// Buffer for incomplete blocks
    buffer: [u8; RATE],
    /// Current number of bytes in the buffer
    buffer_len: usize,
}

impl Sha3_256 {
    /// Creates a new SHA3-256 hasher instance with initialized state
    pub fn new() -> Self {
        Sha3_256 {
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
    /// * A 32-byte array containing the SHA3-256 hash value
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

/// Convenience function to compute the SHA3-256 hash of input data
/// 
/// # Arguments
/// 
/// * `data` - Input data to be hashed
/// 
/// # Returns
/// 
/// * A 32-byte array containing the SHA3-256 hash value
/// 
/// # Example
/// 
/// ```
/// use cryptos::hash::sha3::sha3_256;
/// 
/// let data = b"Hello, world!";
/// let hash = sha3_256(data);
/// ```
pub fn sha3_256(data: &[u8]) -> [u8; HASH_SIZE] {
    let mut hasher = Sha3_256::new();
    hasher.update(data);
    hasher.finalize()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::check::compare_check;
    use crate::utils::x2x::ToHexExt;

    #[test]
    fn test_sha3_256() {
        let test_cases = vec![
            (
                "".as_bytes().to_vec(),
                "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a".to_string()
            ),
            (
                "Two little mice fell in a bucket of cream. The first mouse quickly gave up and drowned.".as_bytes().to_vec(),
                "ab15ace3db8e896963c5a3563a1088172de6a9aa47021e4dabbdb727b4649176".to_string()
            ),
            (
                "The second mouse, wouldn't quit. He struggled so hard that eventually he churned that cream into butter and crawled out. ".as_bytes().to_vec(),
                "5ddc8bb1a863398e3a448658fcf2b0088e28e03d308fae1f321a38be3bf40bf4".to_string()
            ),
        ];

        let sha3_256_test = |input: &Vec<u8>| {
            let result = sha3_256(input);
            result.to_hex(false)
        };

        assert!(compare_check(test_cases, "SHA3-256", sha3_256_test));
    }
}

