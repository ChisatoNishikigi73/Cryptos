use crate::utils::x2x::bytes_to_base64;

pub fn base64_to_bytes(base64: &str) -> Vec<u8> {
    const BASE64_CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    
    // Create the decoding lookup table
    let mut decode_table = [0u8; 256];
    for (i, &c) in BASE64_CHARS.iter().enumerate() {
        decode_table[c as usize] = i as u8;
    }

    let mut result = Vec::new();
    let mut buf = 0u32;
    let mut bits = 0u32;

    for &c in base64.trim_end_matches('=').as_bytes() {
        // Skip whitespace characters
        if c.is_ascii_whitespace() {
            continue;
        }
        
        // Get the 6-bit value corresponding to the character
        let val = decode_table[c as usize] as u32;
        
        // Add the 6-bit value to the buffer
        buf = (buf << 6) | val;
        bits += 6;

        // When we have accumulated 8 bits or more, extract a byte
        if bits >= 8 {
            bits -= 8;
            result.push((buf >> bits) as u8);
        }
    }

    result
}

/// Trait for converting various types to base64 string
pub trait ToBase64Ext {
    fn to_base64(&self) -> String;
}

impl<F> ToBase64Ext for F
where
    F: Fn() -> Vec<u8>,
{
    fn to_base64(&self) -> String {
        bytes_to_base64(&self())
    }
}

impl ToBase64Ext for [u8] {
    fn to_base64(&self) -> String {
        bytes_to_base64(self)
    }
}

impl<const N: usize> ToBase64Ext for [u8; N] {
    fn to_base64(&self) -> String {
        bytes_to_base64(self)
    }
}
