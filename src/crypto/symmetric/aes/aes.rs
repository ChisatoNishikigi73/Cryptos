//! AES cipher implementation with builder pattern support.
//! Provides a flexible interface for configuring different AES modes and parameters.

pub use crate::utils::x2x::ToBytesExt;
use crate::crypto::symmetric::aes::aes_encryptor::AesEncryptor;

/// Supported AES block cipher modes of operation
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum AesMode {
    NONE,
    ECB,
    CBC,
    CFB,
    OFB,
    CTR,
}

/// Builder for configuring AES cipher parameters
#[derive(Debug, Clone)]
pub struct AesBuilder {
    key: Option<Vec<u8>>,
    mode: Option<AesMode>,
    iv: Option<Vec<u8>>,
    expanded_key: Option<Vec<u8>>,
}

impl Default for AesBuilder {
    fn default() -> Self {
        Self {
            key: None,
            mode: None,
            iv: None,
            expanded_key: None,
        }
    }
}

impl AesBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_key(mut self, key: impl ToBytesExt) -> Self {
        let key = key.to_bytes();
        match key.len() {
            16 | 24 | 32 => {
                self.key = Some(key);
                self
            }
            _ => {
                self.key = None;
                self
            }
        }
    }

    pub fn set_expanded_key(mut self, expanded_key: impl ToBytesExt) -> Self {
        let expanded_key = expanded_key.to_bytes();
        self.expanded_key = Some(expanded_key);
        self
    }

    pub fn set_mode(mut self, mode: &str) -> Self {
        let mode = match mode {
            "ECB" => AesMode::ECB,
            "CBC" => AesMode::CBC,
            "CFB" => AesMode::CFB,
            "OFB" => AesMode::OFB,
            "CTR" => AesMode::CTR,
            _ => AesMode::NONE,
        };
        self.mode = Some(mode);
        self
    }

    pub fn set_iv(mut self, iv: impl ToBytesExt) -> Self {
        let iv = iv.to_bytes();
        if iv.len() != 16 {
            self.iv = None;
            return self;
        }
        self.iv = Some(iv);
        self
    }

    pub fn build(self) -> Result<AesCipher, &'static str> {
        let key = self.key.ok_or("Key must be set to 16, 24, or 32 bytes (128, 192, or 256 bits)")?;
        let mode = self.mode.ok_or("Mode must be set to ECB, CBC, CFB, OFB, or CTR")?;

        if matches!(mode, AesMode::NONE) {
            return Err("Mode must be set to ECB, CBC, CFB, OFB, or CTR");
        }

        if matches!(mode, AesMode::CBC | AesMode::CFB | AesMode::OFB | AesMode::CTR) {
            if self.iv.is_none() {
                return Err("IV must be set for this mode");
            }
        }

        Ok(AesCipher {
            key,
            mode,
            iv: self.iv,
        })
    }
}

#[derive(Debug, Clone)]
pub struct AesCipher {
    key: Vec<u8>,
    mode: AesMode,
    iv: Option<Vec<u8>>,
}

impl AesCipher {
    pub fn builder() -> AesBuilder {
        AesBuilder::new()
    }

    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, &'static str> {
        let cipher = self.clone();
        let encryptor = AesEncryptor::new(cipher)?;
        encryptor.encrypt(plaintext)
    }

    // pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, &'static str> {
    //     let cipher = self.clone();
    //     let encryptor = AesEncryptor::new(cipher)?;
    //     encryptor.decrypt(ciphertext)
    // }

    pub fn get_key(&self) -> &Vec<u8> {
        &self.key
    }

    pub fn get_mode(&self) -> AesMode {
        self.mode
    }

    pub fn get_iv(&self) -> Option<&Vec<u8>> {
        self.iv.as_ref()
    }
}
