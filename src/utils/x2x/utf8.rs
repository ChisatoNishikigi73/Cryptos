/// Convert UTF-8 string to bytes
///
/// # Arguments
///
/// * `s` - The UTF-8 string to convert
///
/// # Returns
///
/// Returns the bytes representing the UTF-8 string
pub fn utf8_to_bytes(s: &str) -> Vec<u8> {
    s.as_bytes().to_vec()
}