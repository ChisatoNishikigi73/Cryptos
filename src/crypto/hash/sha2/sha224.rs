//! SHA-224 implementation
//! 
//! SHA-224 is a cryptographic hash function that was designed by the National Institute of Standards and Technology (NIST)
//! It is a 224-bit hash function that is based on the SHA-256 algorithm, but with a different initial values for the state
//! 
use super::sha2_util::{K32, ch32, maj32, bsig0_32, bsig1_32, ssig0_32, ssig1_32};

const BLOCK_SIZE: usize = 64; // 512 bits = 64 bytes
const HASH_SIZE: usize = 28; // 224 bits = 28 bytes

/// Represents the SHA-224 hash algorithm state.
struct Sha224 {
    state: [u32; 8],
    buffer: [u8; BLOCK_SIZE],
    buffer_len: usize,
    total_len: u64,
}

impl Sha224 {
    /// Creates a new SHA-224 hasher instance.
    pub fn new() -> Self {
        Sha224 {
            state: [
                0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939,
                0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4,
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
    /// A 28-byte array containing the computed SHA-224 hash.
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
        for (chunk, &word) in result.chunks_exact_mut(4).zip(self.state.iter().take(7)) {
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

/// Computes the SHA-224 hash of the input data.
///
/// # Arguments
///
/// * `data` - A byte slice containing the input data to be hashed.
///
/// # Returns
///
/// A 28-byte array containing the computed SHA-224 hash.
pub fn sha224(data: &[u8]) -> [u8; HASH_SIZE] {
    let mut hasher = Sha224::new();
    hasher.update(data);
    hasher.finalize()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::check::compare_check;
    use crate::utils::x2x::ToHexExt;

    #[test]
    fn test_sha224() {
        let test_cases = vec![
            (
                "".as_bytes().to_vec(),
                "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f".to_string()
            ),
            (
                "Let us rewrite everything with rust ".as_bytes().to_vec(),
                "19118a3941c0ec4f65da94543d625b2f4c9d98410a9b9ab93cf5b2bf".to_string()
            ),
            (
                "When life seems hard, the courageous do not lie down and accept defeat; instead, they are all the more determined to struggle for better future.".as_bytes().to_vec(),
                "f7b450b21ef70a055251275ba341a4d602bf994016f1fba9bf78e004".to_string()
            ),
        ];

        let sha224_test = |input: &Vec<u8>| {
            let result = sha224(input);
            result.to_hex(false)
        };

        assert!(compare_check(test_cases, "SHA-224", sha224_test));
    }
}

