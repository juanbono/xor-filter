
pub fn murmur64(mut h: u64) -> u64 {
    h ^= h >> 33;
    h = h.wrapping_mul(0xff51_afd7_ed55_8ccd);
    h ^= h >> 33;
    h = h.wrapping_mul(0xc4ce_b9fe_1a85_ec53);
    h ^= h >> 33;
    h
}

/// returns random number, modifies the seed
pub fn splitmix64(seed: &mut u64) -> u64 {
    *seed = (*seed).wrapping_add(0x9e37_79b9_7f4a_7c15);
    let mut z = *seed;
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^ (z >> 31)
}

pub fn mixsplit(key: u64, seed: u64) -> u64 {
    murmur64(key + seed)
}

pub fn rotl64(n: u64, c: i64) -> u64 {
    (n << (c & 63)) | (n >> ((-c) & 63))
}

pub fn reduce(hash: u32, n: u32) -> u32 {
    // http://lemire.me/blog/2016/06/27/a-fast-alternative-to-the-modulo-reduction/
    let h = hash as u64;
    ((h.wrapping_mul(n as u64)) >> 32) as u32
}

pub fn fingerprint(hash: u64) -> u64 {
    hash ^ (hash >> 32)
}
