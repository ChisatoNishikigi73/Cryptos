//! AES decryption implementation supporting ECB, CBC, CFB, OFB, and CTR modes.
//! Implements AES-128, AES-192, and AES-256 variants with UTF-8 support.

use super::aes::{AesCipher, AesMode};
use crate::crypto::symmetric::aes::aes_util::{INV_SBOX, SBOX, RCON};

#[allow(unused)]
use crate::utils::x2x::{ToBase64Ext, ToHexExt};

/// AES decryption implementation with support for multiple block cipher modes
#[derive(Debug)]
pub struct AesDecryptor {
    cipher: AesCipher,
    expanded_key: Vec<u8>,
}

impl AesDecryptor {
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

    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, &'static str> {
        if ciphertext.is_empty() {
            return Err("Empty ciphertext");
        }

        let decrypted = match self.cipher.get_mode() {
            AesMode::ECB => {
                let dec = self.decrypt_ecb(ciphertext)?;
                self.unpad_pkcs7(&dec)?
            },
            AesMode::CBC => {
                let dec = self.decrypt_cbc(ciphertext)?;
                self.unpad_pkcs7(&dec)?
            },
            AesMode::CFB => self.decrypt_cfb(ciphertext)?,
            AesMode::OFB => self.decrypt_ofb(ciphertext)?,
            AesMode::CTR => self.decrypt_ctr(ciphertext)?,
            AesMode::NONE => return Err("Invalid decryption mode"),
        };

        String::from_utf8(decrypted.clone())
            .map_err(|_| "Invalid UTF-8 sequence")?;

        Ok(decrypted)
    }

    fn decrypt_block(&self, block: &[u8]) -> Result<Vec<u8>, &'static str> {
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
        self.add_round_key(&mut state, rounds);

        for round in (1..rounds).rev() {
            self.inv_shift_rows(&mut state);
            self.inv_sub_bytes(&mut state);
            self.add_round_key(&mut state, round);
            self.inv_mix_columns(&mut state);
        }

        self.inv_shift_rows(&mut state);
        self.inv_sub_bytes(&mut state);
        self.add_round_key(&mut state, 0);

        Ok(state)
    }

    fn inv_sub_bytes(&self, state: &mut [u8]) {
        for byte in state.iter_mut() {
            *byte = INV_SBOX[*byte as usize];
        }
    }

    fn inv_shift_rows(&self, state: &mut [u8]) {
        let mut temp = [0u8; 16];
        temp.copy_from_slice(state);
        
        // Row 1: shift right by 1
        state[1] = temp[13];
        state[5] = temp[1];
        state[9] = temp[5];
        state[13] = temp[9];
        
        // Row 2: shift right by 2
        state[2] = temp[10];
        state[6] = temp[14];
        state[10] = temp[2];
        state[14] = temp[6];
        
        // Row 3: shift right by 3
        state[3] = temp[7];
        state[7] = temp[11];
        state[11] = temp[15];
        state[15] = temp[3];
    }

    fn inv_mix_columns(&self, state: &mut [u8]) {
        for i in 0..4 {
            let s0 = state[i*4];
            let s1 = state[i*4 + 1];
            let s2 = state[i*4 + 2];
            let s3 = state[i*4 + 3];

            state[i*4] = self.gmul(14, s0) ^ self.gmul(11, s1) ^ self.gmul(13, s2) ^ self.gmul(9, s3);
            state[i*4 + 1] = self.gmul(9, s0) ^ self.gmul(14, s1) ^ self.gmul(11, s2) ^ self.gmul(13, s3);
            state[i*4 + 2] = self.gmul(13, s0) ^ self.gmul(9, s1) ^ self.gmul(14, s2) ^ self.gmul(11, s3);
            state[i*4 + 3] = self.gmul(11, s0) ^ self.gmul(13, s1) ^ self.gmul(9, s2) ^ self.gmul(14, s3);
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

    fn unpad_pkcs7(&self, data: &[u8]) -> Result<Vec<u8>, &'static str> {
        if data.is_empty() {
            return Err("Empty data");
        }

        let padding_len = *data.last().unwrap() as usize;
        if padding_len == 0 || padding_len > 16 {
            return Err("Invalid padding");
        }

        let content_len = data.len() - padding_len;
        for &byte in &data[content_len..] {
            if byte != padding_len as u8 {
                return Err("Invalid padding");
            }
        }

        Ok(data[..content_len].to_vec())
    }

    fn decrypt_ecb(&self, ciphertext: &[u8]) -> Result<Vec<u8>, &'static str> {
        if ciphertext.len() % 16 != 0 {
            return Err("Invalid ciphertext length");
        }

        let mut plaintext = Vec::with_capacity(ciphertext.len());
        
        for chunk in ciphertext.chunks(16) {
            let decrypted_block = self.decrypt_block(chunk)?;
            plaintext.extend_from_slice(&decrypted_block);
        }

        Ok(plaintext)
    }

    fn decrypt_cbc(&self, ciphertext: &[u8]) -> Result<Vec<u8>, &'static str> {
        if ciphertext.len() % 16 != 0 {
            return Err("Invalid ciphertext length");
        }

        let iv = self.cipher.get_iv()
            .ok_or("IV is required for CBC mode")?;
        
        let mut plaintext = Vec::with_capacity(ciphertext.len());
        let mut previous = iv.clone();

        for chunk in ciphertext.chunks(16) {
            let mut decrypted_block = self.decrypt_block(chunk)?;
            
            for i in 0..16 {
                decrypted_block[i] ^= previous[i];
            }
            
            plaintext.extend_from_slice(&decrypted_block);
            previous = chunk.to_vec();
        }

        Ok(plaintext)
    }

    fn decrypt_cfb(&self, ciphertext: &[u8]) -> Result<Vec<u8>, &'static str> {
        let iv = self.cipher.get_iv()
            .ok_or("IV is required for CFB mode")?;
        
        let mut plaintext = Vec::with_capacity(ciphertext.len());
        let mut previous = iv.clone();

        for chunk in ciphertext.chunks(16) {
            let encrypted_iv = self.encrypt_block(&previous)?;
            
            for (i, &c) in chunk.iter().enumerate() {
                let p = c ^ encrypted_iv[i];
                plaintext.push(p);
                if i < previous.len() {
                    previous[i] = c;
                }
            }
        }

        Ok(plaintext)
    }

    fn decrypt_ofb(&self, ciphertext: &[u8]) -> Result<Vec<u8>, &'static str> {
        let iv = self.cipher.get_iv()
            .ok_or("IV is required for OFB mode")?;
        
        let mut plaintext = Vec::with_capacity(ciphertext.len());
        let mut block = iv.clone();

        for chunk in ciphertext.chunks(16) {
            block = self.encrypt_block(&block)?;
            
            for (i, &c) in chunk.iter().enumerate() {
                plaintext.push(c ^ block[i]);
            }
        }

        Ok(plaintext)
    }

    fn decrypt_ctr(&self, ciphertext: &[u8]) -> Result<Vec<u8>, &'static str> {
        let nonce = self.cipher.get_iv()
            .ok_or("Nonce is required for CTR mode")?;
        
        let mut plaintext = Vec::with_capacity(ciphertext.len());
        let mut counter_block = nonce.clone();

        for chunk in ciphertext.chunks(16) {
            let encrypted_counter = self.encrypt_block(&counter_block)?;
            
            for (i, &c) in chunk.iter().enumerate() {
                plaintext.push(c ^ encrypted_counter[i]);
            }
            
            for i in (0..16).rev() {
                counter_block[i] = counter_block[i].wrapping_add(1);
                if counter_block[i] != 0 {
                    break;
                }
            }
        }

        Ok(plaintext)
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
        
        state[1] = temp[5];
        state[5] = temp[9];
        state[9] = temp[13];
        state[13] = temp[1];
        
        state[2] = temp[10];
        state[6] = temp[14];
        state[10] = temp[2];
        state[14] = temp[6];
        
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::sha3::sha3_256;
    use crate::hash::md5::md5_base;
    use crate::utils::check::compare_check;
    use crate::utils::x2x::ToBase64Ext;
    use crate::utils::x2x::from_hex;
    fn setup() -> (Vec<u8>, Vec<u8>) {
        let key = sha3_256("Now I am become Death, the destroyer of worlds".as_bytes());
        let iv = md5_base("Song of God".to_base64().as_bytes(), 1);
        println!("Base64 key: {}", key.to_base64());
        println!("Base64 iv: {}", iv.to_base64());
        println!("");
        (key.to_vec(), iv.to_vec())
    }

    #[test]
    fn test_aes_cbc_decryption() {
        let (key, iv) = setup();
        let cipher = AesCipher::builder()
            .set_key(key)
            .set_iv(iv)
            .set_mode("CBC")
            .build()
            .unwrap();

        let test_cases = vec![
            (
                "7e5f69f455cf9696e12012ba75ba7dba64937b1297f563485b7627b855a1306a".to_string(),
                " Sharp tools make good work.".to_string()
            ),
            (
                "0596818fe5b0f0a5ae61822b4107fbf3201a8603097c3cf81a4dc306d7335981".to_string(),
                "Doubt is the key to knowledge.".to_string()
            ),
        ];

        assert!(compare_check(
            test_cases,
            "AES CBC Decryption",
            &|input: &String| {
                let decrypted = cipher.decrypt(&from_hex(&input))
                    .expect("Decryption failed");
                String::from_utf8(decrypted).expect("Invalid UTF-8 sequence")
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
        #[allow(unused_variables)]
        let (key, iv) = setup();
        let cipher = AesCipher::builder()
            .set_key(key)
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
