/// Make a hex string from bytes
///
/// # Arguments
///
/// * `bytes` - The bytes to convert
/// * `uppercase` - If true, use uppercase letters; otherwise use lowercase letters
///
/// # Returns
///
/// Returns the hexadecimal string representation of the bytes
pub fn bytes_to_hex(bytes: &[u8], uppercase: bool) -> String {
    bytes.iter().map(|byte| if uppercase {
        format!("{:02X}", byte)
    } else {
        format!("{:02x}", byte)
    }).collect()
}

/// Convert bytes to base64 string
///
/// # Arguments
///
/// * `bytes` - The bytes to convert
///
/// # Returns
///
/// Returns the base64 string representation of the bytes
pub fn bytes_to_base64(bytes: &[u8]) -> String {
    const BASE64_CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut result = String::new();
    let mut i = 0;
    
    while i < bytes.len() {
        let b1 = bytes[i];
        let b2 = if i + 1 < bytes.len() { bytes[i + 1] } else { 0 };
        let b3 = if i + 2 < bytes.len() { bytes[i + 2] } else { 0 };
        
        // Process the first 6-bit
        result.push(BASE64_CHARS[(b1 >> 2) as usize] as char);
        
        // Process the second 6-bit
        result.push(BASE64_CHARS[((b1 & 0x03) << 4 | b2 >> 4) as usize] as char);
        
        // Process the third 6-bit
        if i + 1 < bytes.len() {
            result.push(BASE64_CHARS[((b2 & 0x0f) << 2 | b3 >> 6) as usize] as char);
        } else {
            result.push('=');
        }
        
        // Process the fourth 6-bit
        if i + 2 < bytes.len() {
            result.push(BASE64_CHARS[(b3 & 0x3f) as usize] as char);
        } else {
            result.push('=');
        }
        
        i += 3;
    }
    
    result
}

/// Convert bytes to UTF-8 string
///
/// # Arguments
///
/// * `bytes` - The bytes to convert
///
/// # Returns
///
/// Returns Result with the UTF-8 string or an error if the bytes are not valid UTF-8
pub fn bytes_to_utf8(bytes: &[u8]) -> Result<String, std::string::FromUtf8Error> {
    String::from_utf8(bytes.to_vec())
}

/// Convert bytes to Latin1 string
///
/// # Arguments
///
/// * `bytes` - The bytes to convert
///
/// # Returns
///
/// Returns the Latin1 string
pub fn bytes_to_latin1(bytes: &[u8]) -> String {
    bytes.iter().map(|&b| b as char).collect()
}

/// Trait for converting various types to bytes
pub trait ToBytesExt {
    fn to_bytes(&self) -> Vec<u8>;
}

impl<F> ToBytesExt for F
where
    F: Fn() -> Vec<u8>,
{
    fn to_bytes(&self) -> Vec<u8> {
        self()
    }
}

impl ToBytesExt for [u8] {
    fn to_bytes(&self) -> Vec<u8> {
        self.to_vec()
    }
}

impl<const N: usize> ToBytesExt for [u8; N] {
    fn to_bytes(&self) -> Vec<u8> {
        self.to_vec()
    }
}