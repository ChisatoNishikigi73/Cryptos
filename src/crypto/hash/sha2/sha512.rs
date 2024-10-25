//! SHA-512 implementation
//! 
//! SHA-512 is a cryptographic hash function that was designed by the National Institute of Standards and Technology (NIST)
//! It is a 512-bit hash function that is based on the SHA-256 algorithm, but with a different initial values for the state
//! 
use super::sha2_util::{K64, ch64, maj64, bsig0_64, bsig1_64, ssig0_64, ssig1_64};
#[allow(unused_imports)]
pub use crate::utils::x2x::ToHexExt;

const BLOCK_SIZE: usize = 128; // 1024 bits = 128 bytes
const HASH_SIZE: usize = 64; // 512 bits = 64 bytes

/// Represents the SHA-512 hash algorithm state.
struct Sha512 {
    state: [u64; 8],
    buffer: [u8; BLOCK_SIZE],
    buffer_len: usize,
    total_len: u128,
}

impl Sha512 {
    /// Creates a new SHA-512 hasher instance.
    pub fn new() -> Self {
        Sha512 {
            state: [
                0x6a09e667f3bcc908, 0xbb67ae8584caa73b,
                0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
                0x510e527fade682d1, 0x9b05688c2b3e6c1f,
                0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
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
        self.total_len += data.len() as u128;

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
    /// A 64-byte array containing the computed SHA-512 hash.
    pub fn finalize(&mut self) -> [u8; HASH_SIZE] {
        let bit_len = self.total_len * 8;
        self.update(&[0x80]);

        if self.buffer_len > 112 {
            self.buffer[self.buffer_len..].fill(0);
            let buffer = self.buffer.clone();
            self.process_block(&buffer);
            self.buffer.fill(0);
        } else {
            self.buffer[self.buffer_len..].fill(0);
        }

        self.buffer[112..].copy_from_slice(&bit_len.to_be_bytes());
        let buffer = self.buffer.clone();
        self.process_block(&buffer);

        let mut result = [0; HASH_SIZE];
        for (chunk, &word) in result.chunks_exact_mut(8).zip(self.state.iter()) {
            chunk.copy_from_slice(&word.to_be_bytes());
        }
        result
    }

    /// Processes a single 1024-bit block of data.
    ///
    /// # Arguments
    ///
    /// * `block` - A 128-byte slice representing the block to be processed.
    fn process_block(&mut self, block: &[u8]) {
        let mut w = [0u64; 80];
        for (i, chunk) in block.chunks_exact(8).enumerate().take(16) {
            w[i] = u64::from_be_bytes(chunk.try_into().unwrap());
        }

        for i in 16..80 {
            w[i] = ssig1_64(w[i-2])
                .wrapping_add(w[i-7])
                .wrapping_add(ssig0_64(w[i-15]))
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

        for i in 0..80 {
            let t1 = h
                .wrapping_add(bsig1_64(e))
                .wrapping_add(ch64(e, f, g))
                .wrapping_add(K64[i])
                .wrapping_add(w[i]);
            let t2 = bsig0_64(a).wrapping_add(maj64(a, b, c));
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

/// Computes the SHA-512 hash of the input data.
///
/// # Arguments
///
/// * `data` - A byte slice containing the input data to be hashed.
///
/// # Returns
///
/// A 64-byte array containing the computed SHA-512 hash.
pub fn sha512(data: &[u8]) -> [u8; HASH_SIZE] {
    let mut hasher = Sha512::new();
    hasher.update(data);
    hasher.finalize()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::check::compare_check;

    #[test]
    fn test_sha512() {
        let test_cases = vec![
            (
                "".as_bytes().to_vec(),
                "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e".to_string()
            ),
            (
                "You want to play? Let's play! ".as_bytes().to_vec(),
                "8986d494882b5d5ec81f65abd0172ca6e6cd1c034b34c0a808fa3e11ea66feac7a2165d2a1bf118c9d2b4548c8c6325061d6f397820beb56d1a66dcd0fff8e9f".to_string()
            ),
            (
                "When the world is on fire, we need to be on fire too!".as_bytes().to_vec(),
                "93c6bccf20db10c162f7483a46f6e273b89db43281863401348b8e0ea3a22904dbad65b68aa78a97ddc21825e9087e330fecc9f396a87af9bf026bb757b1e318".to_string()
            ),
        ];

        let sha512_test = |input: &Vec<u8>| {
            let result = sha512(input);
            result.to_hex(false)
        };

        assert!(compare_check(test_cases, "SHA-512", sha512_test));
    }
}