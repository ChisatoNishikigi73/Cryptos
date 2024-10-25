//! AES encryption implementation supporting ECB, CBC, CFB, OFB, and CTR modes.
//! Implements AES-128, AES-192, and AES-256 variants.

use super::aes::{AesCipher, AesMode};
#[allow(unused)]
use crate::utils::x2x::{ToBase64Ext, ToHexExt};

// AES S-box
const SBOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

// Rcon used in key expansion
const RCON: [u8; 10] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];

/// AES encryption implementation with support for multiple block cipher modes
#[derive(Debug)]
pub struct AesEncryptor {
    cipher: AesCipher,
    expanded_key: Vec<u8>,
}

impl AesEncryptor {
    pub fn new(cipher_in: AesCipher) -> Result<Self, &'static str> {
        let key = cipher_in.get_key();
        let expanded_key = Self::expand_key(key)?;
        
        Ok(Self { cipher: cipher_in, expanded_key })
    }

    fn expand_key(key: &[u8]) -> Result<Vec<u8>, &'static str> {
        let key_len = key.len();
        let rounds = match key_len {
            16 => 10,
            24 => 12,
            32 => 14,
            _ => return Err("Invalid key length"),
        };

        let expanded_key_size = 16 * (rounds + 1);
        let mut expanded_key = vec![0u8; expanded_key_size];
        expanded_key[..key_len].copy_from_slice(key);

        let mut i = key_len;
        let mut temp = [0u8; 4];

        while i < expanded_key_size {
            // Copy last 4 bytes to temp
            temp.copy_from_slice(&expanded_key[i-4..i]);

            if i % key_len == 0 {
                // Rotate word
                let t = temp[0];
                temp[0] = temp[1];
                temp[1] = temp[2];
                temp[2] = temp[3];
                temp[3] = t;

                // Apply S-box
                for j in 0..4 {
                    temp[j] = SBOX[temp[j] as usize];
                }

                // XOR with Rcon
                temp[0] ^= RCON[(i / key_len - 1) as usize];
            } else if key_len > 24 && i % key_len == 16 {
                // Additional S-box for 256-bit keys
                for j in 0..4 {
                    temp[j] = SBOX[temp[j] as usize];
                }
            }

            // XOR with earlier block
            for j in 0..4 {
                expanded_key[i + j] = expanded_key[i - key_len + j] ^ temp[j];
            }

            i += 4;
        }

        Ok(expanded_key)
    }

    /// Encrypts data using the configured AES mode
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, &'static str> {
        if plaintext.is_empty() {
            return Err("Empty plaintext");
        }

        match self.cipher.get_mode() {
            AesMode::ECB => self.encrypt_ecb(&self.pad_pkcs7(plaintext)),
            AesMode::CBC => self.encrypt_cbc(&self.pad_pkcs7(plaintext)),
            AesMode::CFB => self.encrypt_cfb(plaintext),
            AesMode::OFB => self.encrypt_ofb(plaintext),
            AesMode::CTR => self.encrypt_ctr(plaintext),
            AesMode::NONE => Err("Invalid encryption mode"),
        }
    }

    fn pad_pkcs7(&self, data: &[u8]) -> Vec<u8> {
        let block_size = 16;
        let padding_len = block_size - (data.len() % block_size);
        let mut padded = Vec::with_capacity(data.len() + padding_len);
        padded.extend_from_slice(data);
        padded.resize(data.len() + padding_len, padding_len as u8);
        padded
    }

    fn encrypt_block(&self, block: &[u8]) -> Result<Vec<u8>, &'static str> {
        if block.len() != 16 {
            return Err("Block size must be 16 bytes");
        }

        let rounds = match self.cipher.get_key().len() {
            16 => 10,
            24 => 12,
            32 => 14,
            _ => return Err("Invalid key length"),
        };

        let mut state = block.to_vec();
        self.add_round_key(&mut state, 0);

        for round in 1..rounds {
            self.sub_bytes(&mut state);
            self.shift_rows(&mut state);
            self.mix_columns(&mut state);
            self.add_round_key(&mut state, round);
        }

        self.sub_bytes(&mut state);
        self.shift_rows(&mut state);
        self.add_round_key(&mut state, rounds);

        Ok(state)
    }

    fn sub_bytes(&self, state: &mut [u8]) {
        for byte in state.iter_mut() {
            *byte = SBOX[*byte as usize];
        }
    }

    fn shift_rows(&self, state: &mut [u8]) {
        let mut temp = [0u8; 16];
        temp.copy_from_slice(state);
        
        // Row 1: shift left by 1
        state[1] = temp[5];
        state[5] = temp[9];
        state[9] = temp[13];
        state[13] = temp[1];
        
        // Row 2: shift left by 2
        state[2] = temp[10];
        state[6] = temp[14];
        state[10] = temp[2];
        state[14] = temp[6];
        
        // Row 3: shift left by 3
        state[3] = temp[15];
        state[7] = temp[3];
        state[11] = temp[7];
        state[15] = temp[11];
    }

    fn mix_columns(&self, state: &mut [u8]) {
        for i in 0..4 {
            let s0 = state[i*4];
            let s1 = state[i*4 + 1];
            let s2 = state[i*4 + 2];
            let s3 = state[i*4 + 3];

            state[i*4] = self.gmul(2, s0) ^ self.gmul(3, s1) ^ s2 ^ s3;
            state[i*4 + 1] = s0 ^ self.gmul(2, s1) ^ self.gmul(3, s2) ^ s3;
            state[i*4 + 2] = s0 ^ s1 ^ self.gmul(2, s2) ^ self.gmul(3, s3);
            state[i*4 + 3] = self.gmul(3, s0) ^ s1 ^ s2 ^ self.gmul(2, s3);
        }
    }

    #[inline(always)]
    fn gmul(&self, mut a: u8, mut b: u8) -> u8 {
        let mut p = 0u8;
        while a != 0 && b != 0 {
            if b & 1 != 0 {
                p ^= a;
            }
            let hi_bit_set = a & 0x80 != 0;
            a <<= 1;
            if hi_bit_set {
                a ^= 0x1b;
            }
            b >>= 1;
        }
        p
    }

    fn add_round_key(&self, state: &mut [u8], round: usize) {
        let start = round * 16;
        for i in 0..16 {
            state[i] ^= self.expanded_key[start + i];
        }
    }

    fn encrypt_ecb(&self, plaintext: &[u8]) -> Result<Vec<u8>, &'static str> {
        let mut ciphertext = Vec::with_capacity(plaintext.len());
        
        for chunk in plaintext.chunks(16) {
            let encrypted_block = self.encrypt_block(chunk)?;
            ciphertext.extend_from_slice(&encrypted_block);
        }

        Ok(ciphertext)
    }

    fn encrypt_cbc(&self, plaintext: &[u8]) -> Result<Vec<u8>, &'static str> {
        let iv = self.cipher.get_iv()
            .ok_or("IV is required for CBC mode")?;
        
        let mut ciphertext = Vec::with_capacity(plaintext.len());
        let mut previous = iv.clone();

        for chunk in plaintext.chunks(16) {
            let mut block = Vec::with_capacity(16);
            for (p, v) in chunk.iter().zip(previous.iter()) {
                block.push(p ^ v);
            }
            
            let encrypted_block = self.encrypt_block(&block)?;
            ciphertext.extend_from_slice(&encrypted_block);
            previous = encrypted_block;
        }

        Ok(ciphertext)
    }

    fn encrypt_cfb(&self, plaintext: &[u8]) -> Result<Vec<u8>, &'static str> {
        let iv = self.cipher.get_iv()
            .ok_or("IV is required for CFB mode")?;
        
        let mut ciphertext = Vec::with_capacity(plaintext.len());
        let mut previous = iv.clone();

        for chunk in plaintext.chunks(16) {
            let encrypted_iv = self.encrypt_block(&previous)?;
            
            for (i, (&p, &v)) in chunk.iter().zip(encrypted_iv.iter()).enumerate() {
                let c = p ^ v;
                ciphertext.push(c);
                previous[i] = c;
            }

            // If the last chunk is less than 16 bytes, keep the remaining part of previous unchanged
        }

        Ok(ciphertext)
    }

    fn encrypt_ofb(&self, plaintext: &[u8]) -> Result<Vec<u8>, &'static str> {
        let iv = self.cipher.get_iv()
            .ok_or("IV is required for OFB mode")?;
        
        let mut ciphertext = Vec::with_capacity(plaintext.len());
        let mut block = iv.clone();

        for chunk in plaintext.chunks(16) {
            block = self.encrypt_block(&block)?;
            let mut encrypted_block = Vec::with_capacity(16);
            
            for (p, v) in chunk.iter().zip(block.iter()) {
                encrypted_block.push(p ^ v);
            }
            
            ciphertext.extend_from_slice(&encrypted_block);
        }

        Ok(ciphertext)
    }

    fn encrypt_ctr(&self, plaintext: &[u8]) -> Result<Vec<u8>, &'static str> {
        let nonce = self.cipher.get_iv()
            .ok_or("Nonce is required for CTR mode")?;
        
        let mut ciphertext = Vec::with_capacity(plaintext.len());
        let mut counter_block = nonce.clone();

        for chunk in plaintext.chunks(16) {
            let encrypted_counter = self.encrypt_block(&counter_block)?;
            
            for (i, &p) in chunk.iter().enumerate() {
                ciphertext.push(p ^ encrypted_counter[i]);
            }
            
            for i in (0..16).rev() {
                counter_block[i] = counter_block[i].wrapping_add(1);
                if counter_block[i] != 0 {
                    break;
                }
            }
        }

        Ok(ciphertext)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::sha3::sha3_256;
    use crate::hash::md5::md5_base;
    use crate::utils::check::compare_check;
    use crate::utils::x2x::ToBase64Ext;

    fn setup() -> (Vec<u8>, Vec<u8>) {
        let key = sha3_256("Now I am become Death, the destroyer of worlds".as_bytes());
        let iv = md5_base("Song of God".to_base64().as_bytes(), 1);
        println!("Base64 key: {}", key.to_base64());
        println!("Base64 iv: {}", iv.to_base64());
        (key.to_vec(), iv.to_vec())
    }

    #[test]
    fn test_aes_cbc_encryption() {
        let (key, iv) = setup();
        let cipher = AesCipher::builder()
            .set_key(key)
            .set_iv(iv)
            .set_mode("CBC")
            .build()
            .unwrap();

        let test_cases = vec![
            (
                " Sharp tools make good work.".to_string(),
                "7e5f69f455cf9696e12012ba75ba7dba64937b1297f563485b7627b855a1306a".to_string()
            ),
            (
                "Doubt is the key to knowledge.".to_string(),
                "0596818fe5b0f0a5ae61822b4107fbf3201a8603097c3cf81a4dc306d7335981".to_string()
            ),
        ];

        assert!(compare_check(
            test_cases,
            "AES CBC Encryption",
            &|input: &String| {
                let encrypted = cipher.encrypt(input.as_bytes())
                    .expect("Encryption failed");
                encrypted.to_hex(false)
            }
        ));
    }

    #[test]
    fn test_aes_cfb_encryption() {
        let (key, iv) = setup();
        let cipher = AesCipher::builder()
            .set_key(key)
            .set_iv(iv)
            .set_mode("CFB")
            .build()
            .unwrap();

        let test_cases = vec![
            (
                "Sharp tools make good work.".to_string(),
                "6407f3ca8fe12407bee2e35b60f8ba28fec157df66d71724e860ae".to_string()
            ),
            (
                "Doubt is the key to knowledge.".to_string(),
                "7300e7da8be1391bf1faf81e2df2b434911c36284451445d15ddabb9ca51".to_string()
            ),
        ];

        assert!(compare_check(
            test_cases,
            "AES CFB Encryption",
            &|input: &String| {
                let encrypted = cipher.encrypt(input.as_bytes())
                    .expect("Encryption failed");
                encrypted.to_hex(false)
            }
        ));
    }

    #[test]
    fn test_aes_ofb_encryption() {
        let (key, iv) = setup();
        let cipher = AesCipher::builder()
            .set_key(key)
            .set_iv(iv)
            .set_mode("OFB")
            .build()
            .unwrap();

        let test_cases = vec![
            (
                "Sharp tools make good work.".to_string(),
                "6407f3ca8fe12407bee2e35b60f8ba2816b2fce9d895da6865d74e".to_string()
            ),
            (
                "Doubt is the key to knowledge.".to_string(),
                "7300e7da8be1391bf1faf81e2df2b43416a1fca6d7dbc2707bd90477a3f2".to_string()
            ),
        ];

        assert!(compare_check(
            test_cases,
            "AES OFB Encryption",
            &|input: &String| {
                let encrypted = cipher.encrypt(input.as_bytes())
                    .expect("Encryption failed");
                encrypted.to_hex(false)
            }
        ));
    }

    #[test]
    fn test_aes_ctr_encryption() {
        let (key, iv) = setup();
        let cipher = AesCipher::builder()
            .set_key(key)
            .set_iv(iv)
            .set_mode("CTR")
            .build()
            .unwrap();

        let test_cases = vec![
            (
                "Sharp tools make good work.".to_string(),
                "6407f3ca8fe12407bee2e35b60f8ba28fe3eb90f14621a6c6ebfbd".to_string()
            ),
            (
                "Doubt is the key to knowledge.".to_string(),
                "7300e7da8be1391bf1faf81e2df2b434fe2db9401b2c027470b1f767e034".to_string()
            ),
        ];

        assert!(compare_check(
            test_cases,
            "AES CTR Encryption",
            &|input: &String| {
                let encrypted = cipher.encrypt(input.as_bytes())
                    .expect("Encryption failed");
                encrypted.to_hex(false)
            }
        ));
    }

    #[test]
    fn test_aes_ecb_encryption() {
        let (key, iv) = setup();
        let cipher = AesCipher::builder()
            .set_key(key)
            .set_iv(iv)
            .set_mode("ECB")
            .build()
            .unwrap();

        let test_cases = vec![
            (
                "Sharp tools make good work.".to_string(),
                "9c5cd5d1cf21deca7575afb82938bc7216cc68f6be230bbb733104704df59289".to_string()
            ),
            (
                "Doubt is the key to knowledge.".to_string(),
                "89285b8e21b3e9fcc5caf6d92079718764b442c5e0c4ab12fe887549c0e6277b".to_string()
            ),
        ];

        assert!(compare_check(
            test_cases,
            "AES ECB Encryption",
            &|input: &String| {
                let encrypted = cipher.encrypt(input.as_bytes())
                    .expect("Encryption failed");
                encrypted.to_hex(false)
            }
        ));
    }
}