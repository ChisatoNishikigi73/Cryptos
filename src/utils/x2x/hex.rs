use crate::utils::x2x::bytes_to_hex;

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
    let hex = hex.replace("0x", "").replace(" ", "");
    
    if hex.len() % 2 != 0 {
        return Vec::new();
    }

    let mut bytes = Vec::with_capacity(hex.len() / 2);
    for chunk in hex.as_bytes().chunks(2) {
        if let Some(byte) = std::str::from_utf8(chunk)
            .ok()
            .and_then(|s| u8::from_str_radix(s, 16).ok())
        {
            bytes.push(byte);
        }
    }
    bytes
}

/// Trait
pub trait ToHexExt {
    /// Converts the implementing type to a hexadecimal string.
    ///
    /// # Arguments
    ///
    /// * `uppercase` - If true, the hexadecimal string will use uppercase letters; otherwise, lowercase letters will be used.
    ///
    /// # Returns
    ///
    /// A `String` containing the hexadecimal representation of the implementing type.
    #[allow(dead_code)]
    fn to_hex(&self, uppercase: bool) -> String;
}

/// Implementation of `ToHexExt` for functions that return `Vec<u8>`.
impl<F> ToHexExt for F
where
    F: Fn() -> Vec<u8>,
{
    fn to_hex(&self, uppercase: bool) -> String {
        let bytes = self();
        bytes_to_hex(&bytes, uppercase)
    }
}

/// Implementation of `ToHexExt` for byte slices `&[u8]`.
impl ToHexExt for &[u8] {
    fn to_hex(&self, uppercase: bool) -> String {
        bytes_to_hex(self, uppercase)
    }
}

/// Implementation of `ToHexExt` for fixed-size byte arrays.
impl<const N: usize> ToHexExt for [u8; N] {
    fn to_hex(&self, uppercase: bool) -> String {
        bytes_to_hex(self, uppercase)
    }
}

impl ToHexExt for String {
    fn to_hex(&self, uppercase: bool) -> String {
        bytes_to_hex(self.as_bytes(), uppercase)
    }
}

impl ToHexExt for Vec<u8> {
    fn to_hex(&self, uppercase: bool) -> String {
        bytes_to_hex(self, uppercase)
    }
}

pub fn from_hex(hex: &str) -> Vec<u8> {
    hex_to_bytes(hex)
}
