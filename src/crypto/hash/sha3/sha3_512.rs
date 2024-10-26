//! SHA3-512 implementation
//! SHA3-512 is part of the SHA-3 family of cryptographic hash functions,
//! standardized by NIST in FIPS 202.

use super::sha3_util::{RC, keccak_f1600_round};

/// Rate in bytes (576 bits) for SHA3-512
/// Rate represents the portion of the state that is used for absorbing input
#[allow(unused)]
const RATE: usize = 72;

/// Capacity in bytes (1024 bits) for SHA3-512
/// Capacity represents the security parameter of the hash function
/// Rate + Capacity = 1600 bits (200 bytes), which is the state size of Keccak-f[1600]
#[allow(unused)]
const CAPACITY: usize = 128;

/// Output size in bytes (512 bits) for SHA3-512
#[allow(unused)]
const HASH_SIZE: usize = 64;

/// SHA3-512 hasher implementation
/// 
/// This struct maintains the internal state of the SHA3-512 hash computation.
/// The state consists of a 5x5 array of 64-bit words (1600 bits total),
/// a buffer for incomplete blocks, and the current buffer length.
pub struct Sha3_512 {
    /// Main state array (5x5 matrix of 64-bit words)
    state: [[u64; 5]; 5],
    /// Buffer for incomplete blocks
    buffer: [u8; RATE],
    /// Current number of bytes in the buffer
    buffer_len: usize,
}

impl Sha3_512 {
    /// Creates a new SHA3-512 hasher instance with initialized state
    pub fn new() -> Self {
        Sha3_512 {
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
    /// * A 64-byte array containing the SHA3-512 hash value
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

/// Convenience function to compute the SHA3-512 hash of input data
/// 
/// # Arguments
/// 
/// * `data` - Input data to be hashed
/// 
/// # Returns
/// 
/// * A 64-byte array containing the SHA3-512 hash value
/// 
/// # Example
/// 
/// ```
/// use cryptos::hash::sha3::sha3_512;
/// 
/// let data = b"Hello, world!";
/// let hash = sha3_512(data);
/// ```
pub fn sha3_512(data: &[u8]) -> [u8; HASH_SIZE] {
    let mut hasher = Sha3_512::new();
    hasher.update(data);
    hasher.finalize()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::check::compare_check;
    use crate::utils::x2x::ToHexExt;

    #[test]
    fn test_sha3_512() {
        let test_cases = vec![
            (
                "".as_bytes().to_vec(),
                "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26".to_string()
            ),
            (
                " 美しく最後を飾りつける暇があるなら最後まで美しく生きようじゃねーか".as_bytes().to_vec(),
                "42e299487f10b612eab4ecd381a7a8e7a86e46a0e58512d1424c1261286a8b4e8ce00f93ad5e6d664a9b2e01bc42cd0f521fb6b0233efb5d680e39502e4721fa".to_string()
            ),
            (
                "私たちの孤独は空に浮かんでいる都市のようです。まるで秘密のようですが、何も言えません".as_bytes().to_vec(),
                "18caa595ca99cd5c910242a1e00d12d34adb4be3d73cd0c946cd268c617025e5c74c667eff8e6b45c01258ccf7f4742803419ed521d8584726857216b0c421ba".to_string()
            ),
        ];

        let sha3_512_test = |input: &Vec<u8>| {
            let result = sha3_512(input);
            result.to_hex(false)
        };

        assert!(compare_check(test_cases, "SHA3-512", sha3_512_test));
    }
}

