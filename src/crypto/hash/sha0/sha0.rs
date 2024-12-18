//! SHA-0 implementation
//! 
//! SHA-0 is a cryptographic hash function that was designed by the National Institute of Standards and Technology (NIST)
//! It is a 160-bit hash function that is based on the SHA-1 algorithm, but with a different initial values for the state
//! 
const BLOCK_SIZE: usize = 64; // 512 bits = 64 bytes
const HASH_SIZE: usize = 20; // 160 bits = 20 bytes

/// Represents the SHA-0 hash algorithm state.
struct Sha0 {
    state: [u32; 5],
    buffer: [u8; BLOCK_SIZE],
    buffer_len: usize,
    total_len: u64,
}

impl Sha0 {
    /// Creates a new SHA-0 hasher instance.
    pub fn new() -> Self {
        Sha0 {
            state: [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0],
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
    fn update(&mut self, data: &[u8]) {
        let mut data_index = 0;
        self.total_len += data.len() as u64;

        if self.buffer_len > 0 {
            let to_copy = (BLOCK_SIZE - self.buffer_len).min(data.len());
            self.buffer[self.buffer_len..self.buffer_len + to_copy].copy_from_slice(&data[..to_copy]);
            self.buffer_len += to_copy;
            data_index += to_copy;

            if self.buffer_len == BLOCK_SIZE {
                let buffer_copy = self.buffer;
                self.process_block(&buffer_copy);
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
    /// A 20-byte array containing the computed SHA-0 hash.
    pub fn finalize(&mut self) -> [u8; HASH_SIZE] {
        let bit_len = self.total_len * 8;
        self.update(&[0x80]);

        if self.buffer_len > 56 {
            self.buffer[self.buffer_len..].fill(0);
            let buffer_copy = self.buffer;
            self.process_block(&buffer_copy);
            self.buffer.fill(0);
        } else {
            self.buffer[self.buffer_len..].fill(0);
        }

        self.buffer[56..].copy_from_slice(&bit_len.to_be_bytes());
        let buffer_copy = self.buffer;
        self.process_block(&buffer_copy);

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
        let mut w = [0u32; 80];
        for (i, chunk) in block.chunks_exact(4).enumerate().take(16) {
            w[i] = u32::from_be_bytes(chunk.try_into().unwrap());
        }

        // The main difference is here: SHA-0 does not perform the circular left shift operation
        for i in 16..80 {
            w[i] = w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16];
        }

        let mut a = self.state[0];
        let mut b = self.state[1];
        let mut c = self.state[2];
        let mut d = self.state[3];
        let mut e = self.state[4];

        for i in 0..80 {
            let (f, k) = match i {
                0..=19 => ((b & c) | ((!b) & d), 0x5A827999),
                20..=39 => (b ^ c ^ d, 0x6ED9EBA1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1BBCDC),
                60..=79 => (b ^ c ^ d, 0xCA62C1D6),
                _ => unreachable!(),
            };

            let temp = a.rotate_left(5).wrapping_add(f).wrapping_add(e).wrapping_add(k).wrapping_add(w[i]);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }

        self.state[0] = self.state[0].wrapping_add(a);
        self.state[1] = self.state[1].wrapping_add(b);
        self.state[2] = self.state[2].wrapping_add(c);
        self.state[3] = self.state[3].wrapping_add(d);
        self.state[4] = self.state[4].wrapping_add(e);
    }
}

/// Computes the SHA-0 hash of the input data.
///
/// # Arguments
///
/// * `data` - A byte slice containing the input data to be hashed.
///
/// # Returns
///
/// A 20-byte array containing the computed SHA-0 hash.
pub fn sha0(data: &[u8]) -> [u8; HASH_SIZE] {
    let mut hasher = Sha0::new();
    hasher.update(data);
    hasher.finalize()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::check::compare_check;
    use crate::utils::x2x::ToHexExt;

    #[test]
    fn test_sha0() {
        let test_cases = vec![
            (
                "".as_bytes().to_vec(),
                "f96cea198ad1dd5617ac084a3d92c6107708c0ef".to_string()
            ),
            (
                " A ruler who hides behind paid executioners soon forgets what death is.".as_bytes().to_vec(),
                "7d5c6467aca17742db08a10673eabdd16b719fef".to_string()
            ),
            (
                "Death is so terribly final, while life is full of possibilities. *(=-c".as_bytes().to_vec(),
                "1ca9f9fd1b1e158ffcf71e66d35c3ce726fee11a".to_string()
            ),
        ];

        let sha0_test = |input: &Vec<u8>| {
            let result = sha0(input);
            result.to_hex(false)
        };

        assert!(compare_check(test_cases, "SHA-0", sha0_test));
    }
}

