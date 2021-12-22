#![no_std]
#![cfg_attr(i128, feature(i128_types))]

pub use blake2xb::Blake2xb;
pub use buffered::Blake2b;
pub use hash::Hash;
pub use parameter_block::ParameterBlock;

pub mod blake2xb;
mod buffered;
mod hash;
mod parameter_block;
mod simd;
mod slice_ext;
pub mod unbuffered;

pub const IV: [u64; 8] = [
    0x6A09E667F3BCC908,
    0xBB67AE8584CAA73B,
    0x3C6EF372FE94F82B,
    0xA54FF53A5F1D36F1,
    0x510E527FADE682D1,
    0x9B05688C2B3E6C1F,
    0x1F83D9ABFB41BD6B,
    0x5BE0CD19137E2179,
];

pub fn compress(buffer: &[u64; 16], hash: &mut [u64; 8], counter: (u64, u64), f: (u64, u64)) {
    use simd::u64x4;

    const SIGMA: [[usize; 16]; 10] = [
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
        [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
        [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
        [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
        [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
        [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
        [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
        [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
        [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
        [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
    ];

    #[inline(always)]
    fn round(v: &mut [u64x4; 4], buf: &[u64; 16], s: [usize; 16]) {
        #[inline(always)]
        fn quarter_round(v: &mut [u64x4; 4], rd: u64, rb: u64, m: u64x4) {
            v[0] = v[0] + v[1] + m;
            v[3] = (v[3] ^ v[0]).rotate_right(rd);
            v[2] = v[2] + v[3];
            v[1] = (v[1] ^ v[2]).rotate_right(rb);
        }

        #[inline(always)]
        fn shuffle(v: &mut [u64x4; 4]) {
            v[1] = v[1].shuffle_left_1();
            v[2] = v[2].shuffle_left_2();
            v[3] = v[3].shuffle_left_3();
        }

        #[inline(always)]
        fn unshuffle(v: &mut [u64x4; 4]) {
            v[1] = v[1].shuffle_right_1();
            v[2] = v[2].shuffle_right_2();
            v[3] = v[3].shuffle_right_3();
        }

        quarter_round(v, 32, 24, u64x4(buf[s[0]], buf[s[2]], buf[s[4]], buf[s[6]]));
        quarter_round(v, 16, 63, u64x4(buf[s[1]], buf[s[3]], buf[s[5]], buf[s[7]]));
        shuffle(v);
        quarter_round(
            v,
            32,
            24,
            u64x4(buf[s[8]], buf[s[10]], buf[s[12]], buf[s[14]]),
        );
        quarter_round(
            v,
            16,
            63,
            u64x4(buf[s[9]], buf[s[11]], buf[s[13]], buf[s[15]]),
        );
        unshuffle(v);
    }

    let mut v = [
        u64x4(hash[0], hash[1], hash[2], hash[3]),
        u64x4(hash[4], hash[5], hash[6], hash[7]),
        u64x4(IV[0], IV[1], IV[2], IV[3]),
        u64x4(
            IV[4] ^ counter.0,
            IV[5] ^ counter.1,
            IV[6] ^ f.0,
            IV[7] ^ f.1,
        ),
    ];

    round(&mut v, buffer, SIGMA[0]);
    round(&mut v, buffer, SIGMA[1]);
    round(&mut v, buffer, SIGMA[2]);
    round(&mut v, buffer, SIGMA[3]);
    round(&mut v, buffer, SIGMA[4]);
    round(&mut v, buffer, SIGMA[5]);
    round(&mut v, buffer, SIGMA[6]);
    round(&mut v, buffer, SIGMA[7]);
    round(&mut v, buffer, SIGMA[8]);
    round(&mut v, buffer, SIGMA[9]);
    round(&mut v, buffer, SIGMA[0]);
    round(&mut v, buffer, SIGMA[1]);

    hash[0] ^= v[0].0 ^ v[2].0;
    hash[1] ^= v[0].1 ^ v[2].1;
    hash[2] ^= v[0].2 ^ v[2].2;
    hash[3] ^= v[0].3 ^ v[2].3;
    hash[4] ^= v[1].0 ^ v[3].0;
    hash[5] ^= v[1].1 ^ v[3].1;
    hash[6] ^= v[1].2 ^ v[3].2;
    hash[7] ^= v[1].3 ^ v[3].3;
}

pub fn blake2b(len: usize, data: &[u8]) -> Hash {
    blake2b_keyed(len, &[], data)
}

pub fn blake2b_keyed(len: usize, key: &[u8], data: &[u8]) -> Hash {
    let mut blake2b = Blake2b::keyed(len, key);
    blake2b.update(data);
    blake2b.finish()
}

pub fn blake2xb(len: Option<u32>, data: &[u8]) -> blake2xb::Iter {
    blake2xb_keyed(len, &[], data)
}

pub fn blake2xb_keyed(len: Option<u32>, key: &[u8], data: &[u8]) -> blake2xb::Iter {
    let mut blake2xb = Blake2xb::keyed(len, key);
    blake2xb.update(data);
    blake2xb.finish()
}

pub fn selftest() -> bool {
    const RESULT: [u8; 32] = [
        0xC2, 0x3A, 0x78, 0x00, 0xD9, 0x81, 0x23, 0xBD, 0x10, 0xF5, 0x06, 0xC6, 0x1E, 0x29, 0xDA,
        0x56, 0x03, 0xD7, 0x63, 0xB8, 0xBB, 0xAD, 0x2E, 0x73, 0x7F, 0x5E, 0x76, 0x5A, 0x7B, 0xCC,
        0xD4, 0x75,
    ];

    fn selftest_seq(out: &mut [u8]) {
        let mut a = 0xDEAD4BADu32.wrapping_mul(out.len() as u32);
        let mut b = 1;

        for item in out.iter_mut() {
            let t = a.wrapping_add(b);
            a = b;
            b = t;

            *item = (t >> 24) as u8;
        }
    }

    let mut data = [0u8; 1024];
    let mut key = [0u8; 64];
    let mut hasher = Blake2b::new(32);

    for &i in &[20, 32, 48, 64] {
        selftest_seq(&mut key[..i]);

        for &j in &[0, 3, 128, 129, 255, 1024] {
            selftest_seq(&mut data[..j]);
            hasher.update(&blake2b(i, &data[..j]));
            hasher.update(&blake2b_keyed(i, &key[..i], &data[..j]));
        }
    }

    *hasher.finish() == RESULT
}
