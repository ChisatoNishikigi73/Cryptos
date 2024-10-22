use crate::utils::common;

/// A trait for converting various types to hexadecimal string representation.
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
    fn to_hex(&self, uppercase: bool) -> String;
}

/// Implementation of `ToHexExt` for functions that return `Vec<u8>`.
impl<F> ToHexExt for F
where
    F: Fn() -> Vec<u8>,
{
    fn to_hex(&self, uppercase: bool) -> String {
        let bytes = self();
        common::bytes_to_hex(&bytes, uppercase)
    }
}

/// Implementation of `ToHexExt` for fixed-size byte arrays `[u8; 16]`.
impl ToHexExt for [u8; 16] {
    fn to_hex(&self, uppercase: bool) -> String {
        common::bytes_to_hex(self, uppercase)
    }
}

/// Implementation of `ToHexExt` for byte slices `&[u8]`.
impl ToHexExt for &[u8] {
    fn to_hex(&self, uppercase: bool) -> String {
        common::bytes_to_hex(self, uppercase)
    }
}
