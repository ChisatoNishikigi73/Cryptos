//! Caesar Cipher implementation
//! One of the simplest and most widely known substitution ciphers
//! Each letter in the plaintext is shifted a certain number of places down the alphabet

/// Encrypts the input text using the Caesar cipher
/// 
/// # Arguments
/// 
/// * `text` - The plaintext to be encrypted
/// * `shift` - The number of positions to shift each character (key)
/// 
/// # Returns
/// 
/// * The encrypted text
/// 
/// # Example
/// 
/// ```
/// use cryptos::classical::caesar::{encrypt, decrypt};
/// 
/// let plaintext = "HELLO";
/// let ciphertext = encrypt(&plaintext, 3);
/// let decrypted = decrypt(&ciphertext, 3);
/// 
/// println!("Encrypt: {}", ciphertext);
/// println!("Decrypt: {}", decrypted);
/// ```
pub fn encrypt(text: &str, shift: i32) -> String {
    text.chars()
        .map(|c| shift_char(c, shift))
        .collect()
}

/// Decrypts the input text using the Caesar cipher
/// 
/// # Arguments
/// 
/// * `text` - The ciphertext to be decrypted
/// * `shift` - The number of positions that were shifted (key)
/// 
/// # Returns
/// 
/// * The decrypted text
/// 
/// # Example
/// 
/// ```
/// use cryptos::classical::caesar::decrypt;
/// 
/// let ciphertext = "KHOOR";
/// let plaintext = decrypt(ciphertext, 3);
/// assert_eq!(plaintext, "HELLO");
/// ```
pub fn decrypt(text: &str, shift: i32) -> String {
    // Decryption is just encryption with the opposite shift
    encrypt(text, -shift)
}

/// Helper function to shift a single character
fn shift_char(c: char, shift: i32) -> char {
    if !c.is_ascii_alphabetic() {
        return c;
    }

    let base = if c.is_ascii_uppercase() { b'A' } else { b'a' };
    let mut shifted = (c as u8 - base) as i32 + shift;
    
    // Handle wraparound
    shifted = ((shifted % 26) + 26) % 26;
    
    (shifted as u8 + base) as char
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::check::compare_check_with_params;

    #[test]
    fn test_caesar_cipher() {
        let encrypt_cases = vec![
            (("HELLO", 3), String::from("KHOOR")),
            (("hello world", 1), String::from("ifmmp xpsme")),
            (("XYZ", 3), String::from("ABC")),
            (("Testing 123!", 5), String::from("Yjxynsl 123!")),
            (("", 10), String::from("")),
        ];

        let decrypt_cases = vec![
            (("KHOOR", 3), String::from("HELLO")),
            (("ifmmp xpsme", 1), String::from("hello world")),
            (("ABC", 3), String::from("XYZ")),
            (("Yjxynsl 123!", 5), String::from("Testing 123!")),
            (("", 10), String::from("")),
        ];

        let parser = |(text, shift): &(&str, i32)| -> Vec<String> {
            vec![text.to_string(), shift.to_string()]
        };

        // Test encrypt funcTest
        let encrypt_func = |params: Vec<String>| -> String {
            encrypt(&params[0], params[1].parse::<i32>().unwrap())
        };

        // Test decrypt func
        let decrypt_func = |params: Vec<String>| -> String {
            decrypt(&params[0], params[1].parse::<i32>().unwrap())
        };

        // Run test
        assert!(compare_check_with_params(
            encrypt_cases,
            "Caesar-Enc",
            encrypt_func,
            parser,
        ));

        assert!(compare_check_with_params(
            decrypt_cases,
            "Caesar-Dec",
            decrypt_func,
            parser,
        ));
    }
}
