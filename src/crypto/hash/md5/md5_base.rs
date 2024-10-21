use crate::utils::common::bytes_to_hex;
use std::mem::transmute;
/// Constants used in the MD5 algorithm
const S: [u32; 64] = [
    7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,
    5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,
    4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,
    6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21
];

/// Constants used in the MD5 algorithm
const K: [u32; 64] = [
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
    0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
    0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
    0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
    0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
    0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
    0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
    0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
    0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
];

/// Represents the internal state of the MD5 algorithm
struct MD5State {
    a: u32,
    b: u32,
    c: u32,
    d: u32,
}

impl MD5State {
    /// Creates a new MD5State with initial values
    fn new() -> Self {
        MD5State {
            a: 0x67452301,
            b: 0xefcdab89,
            c: 0x98badcfe,
            d: 0x10325476,
        }
    }
}

/// Computes the MD5 hash of the input data
///
/// # Arguments
///
/// * `input` - A byte slice containing the input data
/// * `rounds` - The number of rounds to process the input
/// # Returns
///
/// A 16-byte array containing the MD5 hash
pub fn md5_base(input: &[u8], rounds: u32) -> [u8; 16] {
    let mut result = process(input);
    for _ in 1..rounds {
        result = process(&result);
    }
    result
}

/// Processes the input data and returns the MD5 hash
///
/// # Arguments
///
/// * `input` - A byte slice containing the input data
/// # Returns
///
/// A 16-byte array containing the MD5 hash
pub fn process(input: &[u8]) -> [u8; 16] {
    let mut state = MD5State::new();
    let mut buffer = Vec::from(input);

    // 填充消息
    let original_len_in_bits = (buffer.len() * 8) as u64;
    buffer.push(0x80);
    while (buffer.len() % 64) != 56 {
        buffer.push(0);
    }
    buffer.extend_from_slice(&original_len_in_bits.to_le_bytes());

    // 处理消息块
    for chunk in buffer.chunks(64) {
        process_chunk(&mut state, chunk);
    }

    // 输出最终结果
    unsafe {
        transmute([state.a.to_le(), state.b.to_le(), state.c.to_le(), state.d.to_le()])
    }
}

/// Processes a 64-byte chunk of data and updates the MD5 state
///
/// # Arguments
///
/// * `state` - The current MD5 state
/// * `chunk` - A 64-byte slice of data to process
fn process_chunk(state: &mut MD5State, chunk: &[u8]) {
    let mut x = [0u32; 16];
    for (i, chunk) in chunk.chunks(4).enumerate() {
        x[i] = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
    }

    let (mut a, mut b, mut c, mut d) = (state.a, state.b, state.c, state.d);

    for i in 0..64 {
        let (f, g) = match i {
            0..=15 => ((b & c) | (!b & d), i),
            16..=31 => ((d & b) | (!d & c), (5 * i + 1) % 16),
            32..=47 => (b ^ c ^ d, (3 * i + 5) % 16),
            _ => (c ^ (b | !d), (7 * i) % 16),
        };

        let temp = d;
        d = c;
        c = b;
        b = b.wrapping_add(
            (a.wrapping_add(f)
                .wrapping_add(K[i])
                .wrapping_add(x[g]))
                .rotate_left(S[i])
        );
        a = temp;
    }

    state.a = state.a.wrapping_add(a);
    state.b = state.b.wrapping_add(b);
    state.c = state.c.wrapping_add(c);
    state.d = state.d.wrapping_add(d);
}

/// Converts a 16-byte MD5 digest to a hexadecimal string
///
/// # Arguments
///
/// * `digest` - The 16-byte MD5 digest
/// * `uppercase` - If true, use uppercase letters; otherwise, use lowercase
///
/// # Returns
///
/// A String containing the hexadecimal representation of the digest
pub fn md5_hex(input: &[u8], rounds: u32, uppercase: bool) -> String {
    bytes_to_hex(&md5_base(input, rounds), uppercase)
}

#[cfg(test)]
pub mod tests {
    #[test]
    pub fn md5_hex_test() {
        use super::*;
        use crate::utils::check::compare_check;

        let test_cases = vec![
            ("".to_string(), "d41d8cd98f00b204e9800998ecf8427e".to_string()),
            ("password".to_string(), "5f4dcc3b5aa765d61d8327deb882cf99".to_string()),
            (" password ".to_string(), "0f2626815dd03c825b8c3b46f2be4e02".to_string()),
            ("message digest".to_string(), "f96b697d7cb7938d525a2f31aaf161d0".to_string()),
            ("abcdefghijklmnopqrstuvwxyz ".to_string(), "cb20bf9177e73d5ffa71e95d22389d6d".to_string()),
            ("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789".to_string(), "d174ab98d277d9f5a5611c2c9f419d9f".to_string()),
        ];

        let result = compare_check(test_cases, "MD5", |input| md5_hex(input.as_bytes(), 1, false));
        assert!(result, "MD5 Test Failed");
    }
}
