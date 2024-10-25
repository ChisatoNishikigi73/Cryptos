/// Convert UTF-8 string to bytes
///
/// # Arguments
///
/// * `s` - The UTF-8 string to convert
///
/// # Returns
///
/// Returns the bytes representing the UTF-8 string
#[allow(dead_code)]
pub fn utf8_to_bytes(s: &str) -> Vec<u8> {
    s.as_bytes().to_vec()
}

#[allow(dead_code)]
pub fn from_utf8(s: &str) -> &[u8] {
    s.as_bytes()
}

#[allow(dead_code)]
pub trait ToUtf8Ext {
    fn to_utf8(&self) -> Vec<u8>;
}

impl<F> ToUtf8Ext for F
where
    F: Fn() -> Vec<u8>,
{
    fn to_utf8(&self) -> Vec<u8> {
        self()
    }
}

impl ToUtf8Ext for &[u8] {
    fn to_utf8(&self) -> Vec<u8> {
        self.to_vec()
    }
}