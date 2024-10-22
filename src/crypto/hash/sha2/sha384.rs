use super::sha2_util::{K64, ch64, maj64, bsig0_64, bsig1_64, ssig0_64, ssig1_64};
#[allow(unused_imports)]
use crate::utils::r#trait::base_trait::ToHexExt;

const BLOCK_SIZE: usize = 128; // 1024 bits = 128 bytes
const HASH_SIZE: usize = 48; // 384 bits = 48 bytes

/// Represents the SHA-384 hash algorithm state.
struct Sha384 {
    state: [u64; 8],
    buffer: [u8; BLOCK_SIZE],
    buffer_len: usize,
    total_len: u128,
}

impl Sha384 {
    /// Creates a new SHA-384 hasher instance.
    pub fn new() -> Self {
        Sha384 {
            state: [
                0xcbbb9d5dc1059ed8, 0x629a292a367cd507,
                0x9159015a3070dd17, 0x152fecd8f70e5939,
                0x67332667ffc00b31, 0x8eb44a8768581511,
                0xdb0c2e0d64f98fa7, 0x47b5481dbefa4fa4,
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
    /// A 48-byte array containing the computed SHA-384 hash.
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
        for (chunk, &word) in result.chunks_exact_mut(8).zip(self.state.iter().take(6)) {
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

/// Computes the SHA-384 hash of the input data.
///
/// # Arguments
///
/// * `data` - A byte slice containing the input data to be hashed.
///
/// # Returns
///
/// A 48-byte array containing the computed SHA-384 hash.
pub fn sha384(data: &[u8]) -> [u8; HASH_SIZE] {
    let mut hasher = Sha384::new();
    hasher.update(data);
    hasher.finalize()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::check::compare_check;

    #[test]
    fn test_sha384() {
        let test_cases = vec![
            (
                "".as_bytes().to_vec(),
                "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b".to_string()
            ),
            (
                "But nothing that can be said can begin to take away the anguish and the pain of these moments. Grief is the price we pay for love. ".as_bytes().to_vec(),
                "868d75041ae91c37ab6ec508f1d6e7b4d716dd78d20d963b50e9d6e04d6c8fabd1ebd99b6d050e9be03324ab6cdaf11e".to_string()
            ),
            (
                " The real talent is resolute aspirations.".as_bytes().to_vec(),
                "d791029a1b9102bc18940adfc30029013a24bcc9ce003e0db29f3ddda37ef13916337499dd3f2eb179a3e110d6ffec86".to_string()
            ),
        ];

        let sha384_test = |input: &Vec<u8>| {
            let result = sha384(input);
            result.to_hex(false)
        };

        assert!(compare_check(test_cases, "SHA-384", sha384_test));
    }
}