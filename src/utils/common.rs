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

/// Convert a hex string to bytes
///
/// # Arguments
///
/// * `hex` - The hex string to convert
///
/// # Returns
///
/// Returns the bytes represented by the hex string
pub fn hex_to_bytes(hex: &str) -> Vec<u8> {
    hex.as_bytes().chunks(2).map(|chunk| u8::from_str_radix(std::str::from_utf8(chunk).unwrap(), 16).unwrap()).collect()
}