use super::md5_base::md5_base;
use crate::utils::common::bytes_to_hex;


/// Performs MD5 crypt operation based on the given password, salt, and pattern.
///
/// This function applies the MD5 hash algorithm according to the specified pattern,
/// which can include nested MD5 operations and concatenations of password and salt.
///
/// # Arguments
///
/// * `password` - A string slice that holds the password to be hashed
/// * `salt` - A string slice that holds the salt to be used in the hashing process
/// * `pattern` - A string slice that specifies the pattern of MD5 operations to be performed
///
/// # Returns
///
/// A `String` containing the hexadecimal representation of the final MD5 hash
///
/// # Examples
///
/// ```
/// let result = md5_crypt("password", "salt", "md5(md5($pass))");
/// assert_eq!(result, "9bf4b3611c53176f5c649aa4fc1ff6b2");
/// ```
pub fn md5_crypt(password: &str, salt: &str, pattern: &str) -> String {
    let result = process_pattern(pattern, password, salt);
    bytes_to_hex(&result, false)
}

/// Processes the given pattern recursively, applying MD5 hash operations as specified.
///
/// This function interprets the pattern string and performs the necessary MD5 operations,
/// including nested hashes and concatenations of password and salt.
///
/// # Arguments
///
/// * `pattern` - A string slice that holds the pattern to be processed
/// * `password` - A string slice that holds the password to be used in the pattern
/// * `salt` - A string slice that holds the salt to be used in the pattern
///
/// # Returns
///
/// A `Vec<u8>` containing the result of processing the pattern
fn process_pattern(pattern: &str, password: &str, salt: &str) -> Vec<u8> {
    if pattern.starts_with("md5(") && pattern.ends_with(')') {
        let inner = &pattern[4..pattern.len() - 1];
        let inner_result = process_pattern(inner, password, salt);
        md5_base(&inner_result, 1).to_vec()
    } else {
        let mut result = Vec::new();
        let parts = pattern.split('.');
        for part in parts {
            result.extend_from_slice(&process_part(part, password, salt));
        }
        result
    }
}

/// Processes a single part of the pattern, which can be a literal string, a variable ($pass or $salt),
/// or a nested MD5 operation.
///
/// # Arguments
///
/// * `part` - A string slice that holds the part to be processed
/// * `password` - A string slice that holds the password to be used if needed
/// * `salt` - A string slice that holds the salt to be used if needed
///
/// # Returns
///
/// A `Vec<u8>` containing the result of processing the part
fn process_part(part: &str, password: &str, salt: &str) -> Vec<u8> {
    match part {
        "$pass" => password.as_bytes().to_vec(),
        "$salt" => salt.as_bytes().to_vec(),
        _ if part.starts_with("md5(") && part.ends_with(')') => {
            let inner = &part[4..part.len() - 1];
            process_pattern(inner, password, salt)
        },
        _ => part.as_bytes().to_vec(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::check::compare_check;

    #[test]
    fn test_md5_crypt() {
        let test_cases = vec![
            (
                (
                    "password".to_string(), 
                    "salt".to_string(), 
                    "md5(md5($pass))".to_string()
                ),
                "9bf4b3611c53176f5c649aa4fc1ff6b2".to_string()
            ),
            (
                (
                    "password".to_string(), 
                    "salt".to_string(), 
                    "md5($pass.$salt)".to_string()
                ),
                "b305cadbb3bce54f3aa59c64fec00dea".to_string()
            ),
            (
                (
                    "password".to_string(), 
                    "salt".to_string(), 
                    "md5($salt.$pass)".to_string()
                ),
                "67a1e09bb1f83f5007dc119c14d663aa".to_string()
            ),
            (
                (
                    "password".to_string(), 
                    "salt".to_string(), 
                    "md5($salt.$pass.$salt)".to_string()
                ),
                "92fb338c1d3147f23652d9ce7daf49f3".to_string()
            )
        ];

        let result = compare_check(
            test_cases,
            "MD5 crypt",
            |(password, salt, pattern)| md5_crypt(password, salt, pattern)
        );

        assert!(result, "MD5 crypt Test Failed");
    }
}
