//! Utility functions and constants for SHA3 implementation
//! These are used by all SHA3 variants (224, 256, 384, 512)

// Keccak-f[1600] round constants
/// Round constants for Keccak-f[1600]
/// Used in the ι (iota) step of the Keccak-f round function
pub const RC: [u64; 24] = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A,
    0x8000000080008000, 0x000000000000808B, 0x0000000080000001,
    0x8000000080008081, 0x8000000000008009, 0x000000000000008A,
    0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089,
    0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
    0x000000000000800A, 0x800000008000000A, 0x8000000080008081,
    0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
];

// Rotation offsets
/// Rotation offsets for the ρ (rho) step
/// These values determine how many positions each lane is rotated
pub const R: [[u32; 5]; 5] = [
    [0, 36, 3, 41, 18],
    [1, 44, 10, 45, 2],
    [62, 6, 43, 15, 61],
    [28, 55, 25, 21, 56],
    [27, 20, 39, 8, 14],
];

/// Performs one round of the Keccak-f[1600] permutation
/// 
/// # Arguments
/// 
/// * `a` - The current state as a 5x5 array of 64-bit words
/// * `rc` - The round constant for this round
/// 
/// The function applies the five steps of Keccak-f:
/// - θ (theta): diffusion step
/// - ρ (rho): rotation of lanes
/// - π (pi): rearrangement of lanes
/// - χ (chi): nonlinear layer
/// - ι (iota): addition of round constant
pub fn keccak_f1600_round(a: &mut [[u64; 5]; 5], rc: u64) {
    // θ step
    let mut c = [0u64; 5];
    let mut d = [0u64; 5];
    
    for x in 0..5 {
        c[x] = a[x][0] ^ a[x][1] ^ a[x][2] ^ a[x][3] ^ a[x][4];
    }
    
    for x in 0..5 {
        d[x] = c[(x + 4) % 5] ^ c[(x + 1) % 5].rotate_left(1);
        for y in 0..5 {
            a[x][y] ^= d[x];
        }
    }

    // ρ and π steps
    let mut b = [[0u64; 5]; 5];
    for x in 0..5 {
        for y in 0..5 {
            let x2 = y;
            let y2 = (2 * x + 3 * y) % 5;
            b[x2][y2] = a[x][y].rotate_left(R[x][y]);
        }
    }

    // χ step
    for x in 0..5 {
        for y in 0..5 {
            a[x][y] = b[x][y] ^ ((!b[(x + 1) % 5][y]) & b[(x + 2) % 5][y]);
        }
    }

    // ι step
    a[0][0] ^= rc;
}
