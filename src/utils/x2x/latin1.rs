/// Convert Latin1 string to bytes
///
/// # Arguments
///
/// * `s` - The Latin1 string to convert
///
/// # Returns
///
/// Returns the bytes representing the Latin1 string
pub fn latin1_to_bytes(s: &str) -> Vec<u8> {
    s.chars().map(|c| c as u8).collect()
}