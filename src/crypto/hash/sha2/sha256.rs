//! SHA-256 implementation
//! 
//! SHA-256 is a cryptographic hash function that was designed by the National Institute of Standards and Technology (NIST)
//! It is a 256-bit hash function that is based on the SHA-256 algorithm
//! 
use super::sha2_util::{K32, ch32, maj32, bsig0_32, bsig1_32, ssig0_32, ssig1_32};
#[allow(unused_imports)]
pub use crate::utils::x2x::ToHexExt;

const BLOCK_SIZE: usize = 64; // 512 bits = 64 bytes
const HASH_SIZE: usize = 32; // 256 bits = 32 bytes

/// Represents the SHA-256 hash algorithm state.
struct Sha256 {
    state: [u32; 8],
    buffer: [u8; BLOCK_SIZE],
    buffer_len: usize,
    total_len: u64,
}

impl Sha256 {
    /// Creates a new SHA-256 hasher instance.
    pub fn new() -> Self {
        Sha256 {
            state: [
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
            ],
            buffer: [0; BLOCK_SIZE],
            buffer_len: 0,
            total_len: 0,
        }
    }

    /// Updates the hash with new data.
    ///
    /// # Arguments
    ///
    /// * `data` - A byte slice containing the data to be hashed.
    pub fn update(&mut self, data: &[u8]) {
        let mut data_index = 0;
        self.total_len += data.len() as u64;

        if self.buffer_len > 0 {
            let to_copy = (BLOCK_SIZE - self.buffer_len).min(data.len());
            self.buffer[self.buffer_len..self.buffer_len + to_copy].copy_from_slice(&data[..to_copy]);
            self.buffer_len += to_copy;
            data_index += to_copy;

            if self.buffer_len == BLOCK_SIZE {
                let buffer = self.buffer.clone();
                self.process_block(&buffer);
                self.buffer_len = 0;
            }
        }

        while data_index + BLOCK_SIZE <= data.len() {
            self.process_block(&data[data_index..data_index + BLOCK_SIZE]);
            data_index += BLOCK_SIZE;
        }

        if data_index < data.len() {
            let remaining = data.len() - data_index;
            self.buffer[..remaining].copy_from_slice(&data[data_index..]);
            self.buffer_len = remaining;
        }
    }

    /// Finalizes the hash computation and returns the hash value.
    ///
    /// # Returns
    ///
    /// A 32-byte array containing the computed SHA-256 hash.
    pub fn finalize(&mut self) -> [u8; HASH_SIZE] {
        let bit_len = self.total_len * 8;
        self.update(&[0x80]);

        if self.buffer_len > 56 {
            self.buffer[self.buffer_len..].fill(0);
            let buffer = self.buffer.clone();
            self.process_block(&buffer);
            self.buffer.fill(0);
        } else {
            self.buffer[self.buffer_len..].fill(0);
        }

        self.buffer[56..].copy_from_slice(&bit_len.to_be_bytes());
        let buffer = self.buffer.clone();
        self.process_block(&buffer);

        let mut result = [0; HASH_SIZE];
        for (chunk, &word) in result.chunks_exact_mut(4).zip(self.state.iter()) {
            chunk.copy_from_slice(&word.to_be_bytes());
        }
        result
    }

    /// Processes a single 512-bit block of data.
    ///
    /// # Arguments
    ///
    /// * `block` - A 64-byte slice representing the block to be processed.
    fn process_block(&mut self, block: &[u8]) {
        let mut w = [0u32; 64];
        for (i, chunk) in block.chunks_exact(4).enumerate().take(16) {
            w[i] = u32::from_be_bytes(chunk.try_into().unwrap());
        }

        for i in 16..64 {
            w[i] = ssig1_32(w[i-2])
                .wrapping_add(w[i-7])
                .wrapping_add(ssig0_32(w[i-15]))
                .wrapping_add(w[i-16]);
        }

        let mut a = self.state[0];
        let mut b = self.state[1];
        let mut c = self.state[2];
        let mut d = self.state[3];
        let mut e = self.state[4];
        let mut f = self.state[5];
        let mut g = self.state[6];
        let mut h = self.state[7];

        for i in 0..64 {
            let t1 = h
                .wrapping_add(bsig1_32(e))
                .wrapping_add(ch32(e, f, g))
                .wrapping_add(K32[i])
                .wrapping_add(w[i]);
            let t2 = bsig0_32(a).wrapping_add(maj32(a, b, c));
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }

        self.state[0] = self.state[0].wrapping_add(a);
        self.state[1] = self.state[1].wrapping_add(b);
        self.state[2] = self.state[2].wrapping_add(c);
        self.state[3] = self.state[3].wrapping_add(d);
        self.state[4] = self.state[4].wrapping_add(e);
        self.state[5] = self.state[5].wrapping_add(f);
        self.state[6] = self.state[6].wrapping_add(g);
        self.state[7] = self.state[7].wrapping_add(h);
    }
}

/// Computes the SHA-256 hash of the input data.
///
/// # Arguments
///
/// * `data` - A byte slice containing the input data to be hashed.
///
/// # Returns
///
/// A 32-byte array containing the computed SHA-256 hash.
pub fn sha256(data: &[u8]) -> [u8; HASH_SIZE] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::check::compare_check;

    #[test]
    fn test_sha256() {
        let test_cases = vec![
            (
                "".as_bytes().to_vec(),
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string()
            ),
            (
                "I'm a barbie girl, in the barbie world ~ ".as_bytes().to_vec(),
                "92a81f2181d4f93e7238389175f01f7fb703a90884bf5ddce75225282c5fb9e1".to_string()
            ),
            (
                " I have a plan ".as_bytes().to_vec(),
                "4f7e90f41460830aad480eb43fb01e725d238d3b16044a7883608f25a3680260".to_string()
            ),
        ];

        let sha256_test = |input: &Vec<u8>| {
            let result = sha256(input);
            result.to_hex(false)
        };

        assert!(compare_check(test_cases, "SHA-256", sha256_test));
    }
}