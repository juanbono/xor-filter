/// Xor8 offers a 0.3% false-positive probability
#[derive(Debug, Clone)]
pub struct Xor8 {
    seed: u64,
    block_length: u32,
    fingerprints: Vec<u8>,
}

impl Xor8 {
    /// Creates a filter with the provided keys.
    /// The caller is responsible to ensure that there are no duplicate keys
    pub fn new(keys: Vec<u64>) -> Self {
        let size = keys.len();
        let mut capacity = 32 + f64::ceil(1.23 * size as f64) as u32;
        capacity = capacity / 3 * 3; // round it down to a multiple of 3
        let mut rngcounter = 1;
        let mut fingerprints = Vec::new();
        fingerprints.resize(capacity as usize, 0);

        let mut filter = Xor8 {
            block_length: capacity / 3,
            fingerprints,
            seed: splitmix64(&mut rngcounter),
        };

        let mut q0: Vec<KeyIndex> = Vec::new();
        q0.resize(filter.block_length as usize, KeyIndex::new(0, 0));
        let mut q1: Vec<KeyIndex> = Vec::new();
        q1.resize(filter.block_length as usize, KeyIndex::new(0, 0));
        let mut q2: Vec<KeyIndex> = Vec::new();
        q2.resize(filter.block_length as usize, KeyIndex::new(0, 0));
        let mut stack: Vec<KeyIndex> = Vec::new();
        stack.resize(size as usize, KeyIndex::new(0, 0));

        let mut sets0: Vec<XorSet> = Vec::new();
        sets0.resize(filter.block_length as usize, XorSet::new(0, 0));
        let mut sets1: Vec<XorSet> = Vec::new();
        sets1.resize(filter.block_length as usize, XorSet::new(0, 0));
        let mut sets2: Vec<XorSet> = Vec::new();
        sets2.resize(filter.block_length as usize, XorSet::new(0, 0));

        loop {
            for k in keys.iter() {
                let key = *k;
                let hs = filter.geth0h1h2(key);
                sets0[hs.h0 as usize].xormask ^= hs.h; //
                sets0[hs.h0 as usize].count += 1;
                sets1[hs.h1 as usize].xormask ^= hs.h;
                sets1[hs.h1 as usize].count += 1;
                sets2[hs.h2 as usize].xormask ^= hs.h;
                sets2[hs.h2 as usize].count += 1;
            }

            // scan for values with a count of one
            let mut q0_size = 0;
            let mut q1_size = 0;
            let mut q2_size = 0;

            for i in 0..filter.block_length {
                if sets0[i as usize].count == 1 {
                    q0[q0_size].index = i;
                    q0[q0_size].hash = sets0[i as usize].xormask;
                    q0_size += 1;
                }
            }

            for i in 0..filter.block_length {
                if sets1[i as usize].count == 1 {
                    q1[q1_size].index = i;
                    q1[q1_size].hash = sets1[i as usize].xormask;
                    q1_size += 1;
                }
            }

            for i in 0..filter.block_length {
                if sets2[i as usize].count == 1 {
                    q2[q2_size].index = i;
                    q2[q2_size].hash = sets2[i as usize].xormask;
                    q2_size += 1;
                }
            }

            let mut stack_size = 0;
            while q0_size + q1_size + q2_size > 0 {
                while q0_size > 0 {
                    q0_size -= 1;
                    let keyindex_var = q0[q0_size];
                    let index = keyindex_var.index;
                    if sets0[index as usize].count == 0 {
                        continue; // not actually possible after the initial scan
                    }
                    let hash = keyindex_var.hash;
                    let h1 = filter.geth1(hash);
                    let h2 = filter.geth2(hash);
                    stack[stack_size] = keyindex_var;
                    stack_size += 1;
                    sets1[h1 as usize].xormask ^= hash;

                    sets1[h1 as usize].count -= 1;
                    if sets1[h1 as usize].count == 1 {
                        q1[q1_size].index = h1;
                        q1[q1_size].hash = sets1[h1 as usize].xormask;
                        q1_size += 1;
                    }

                    sets2[h2 as usize].xormask ^= hash;
                    sets2[h2 as usize].count -= 1;
                    if sets2[h2 as usize].count == 1 {
                        q2[q2_size].index = h2;
                        q2[q2_size].hash = sets2[h2 as usize].xormask;
                        q2_size += 1;
                    }
                }

                while q1_size > 0 {
                    q1_size -= 1;
                    let mut keyindex_var = q1[q1_size];
                    let index = keyindex_var.index;
                    if sets1[index as usize].count == 0 {
                        continue;
                    }
                    let hash = keyindex_var.hash;
                    let h0 = filter.geth0(hash);
                    let h2 = filter.geth2(hash);
                    keyindex_var.index = filter.block_length;
                    stack[stack_size as usize] = keyindex_var;
                    stack_size += 1;
                    sets0[h0 as usize].xormask ^= hash;
                    sets0[h0 as usize].count -= 1;
                    if sets0[h0 as usize].count == 1 {
                        q0[q0_size].index = h0;
                        q0[q0_size].hash = sets0[h0 as usize].xormask;
                        q0_size += 1;
                    }
                    sets2[h2 as usize].xormask ^= hash;
                    sets2[h2 as usize].count -= 1;
                    if sets2[h2 as usize].count == 1 {
                        q2[q2_size].index = h2;
                        q2[q2_size].hash = sets2[h2 as usize].xormask;
                        q2_size += 1;
                    }
                }

                while q2_size > 0 {
                    q2_size -= 1;
                    let mut keyindex_var = q2[q2_size];
                    let index = keyindex_var.index;
                    if sets2[index as usize].count == 0 {
                        continue;
                    }
                    let hash = keyindex_var.hash;
                    let h0 = filter.geth0(hash);
                    let h1 = filter.geth1(hash);
                    keyindex_var.index += 2 * filter.block_length;

                    stack[stack_size as usize] = keyindex_var;
                    stack_size += 1;
                    sets0[h0 as usize].xormask ^= hash;
                    sets0[h0 as usize].count -= 1;
                    if sets0[h0 as usize].count == 1 {
                        q0[q0_size].index = h0;
                        q0[q0_size].hash = sets0[h0 as usize].xormask;
                        q0_size += 1;
                    }
                    sets1[h1 as usize].xormask ^= hash;
                    sets1[h1 as usize].count -= 1;
                    if sets1[h1 as usize].count == 1 {
                        q1[q1_size].index = h1;
                        q1[q1_size].hash = sets1[h1 as usize].xormask;
                        q1_size += 1;
                    }
                }
            }

            if stack_size == size {
                break; // success
            }

            sets0 = sets0.iter().map(|_| XorSet::new(0, 0)).collect();
            sets1 = sets1.iter().map(|_| XorSet::new(0, 0)).collect();
            sets2 = sets2.iter().map(|_| XorSet::new(0, 0)).collect();
            filter.seed = splitmix64(&mut rngcounter);
        }

        let mut stack_size = size;

        while stack_size > 0 {
            stack_size -= 1;
            let ki = stack[stack_size];
            let mut val = fingerprint(ki.hash) as u8;
            if ki.index < filter.block_length {
                val ^= filter.fingerprints[(filter.geth1(ki.hash) + filter.block_length) as usize]
                    ^ filter.fingerprints
                        [(filter.geth2(ki.hash) + 2 * filter.block_length) as usize];
            } else if ki.index < 2 * filter.block_length {
                val ^= filter.fingerprints[filter.geth0(ki.hash) as usize]
                    ^ filter.fingerprints
                        [(filter.geth2(ki.hash) + 2 * filter.block_length) as usize];
            } else {
                val ^= filter.fingerprints[filter.geth0(ki.hash) as usize]
                    ^ filter.fingerprints[(filter.geth1(ki.hash) + filter.block_length) as usize];
            }
            filter.fingerprints[ki.index as usize] = val;
        }
        filter
    }

    /// tells you whether the key is likely part of the set
    pub fn contains(&self, key: u64) -> bool {
        let hash = mixsplit(key, self.seed);
        let f = fingerprint(hash) as u8;
        let r0 = hash as u32;
        let r1 = rotl64(hash, 21) as u32;
        let r2 = rotl64(hash, 42) as u32;
        let h0 = reduce(r0, self.block_length) as u8;
        let h1 = (reduce(r1, self.block_length) + self.block_length) as u8;
        let h2 = (reduce(r2, self.block_length) + 2 * self.block_length) as u8;
        f == (self.fingerprints[h0 as usize]
            ^ self.fingerprints[h1 as usize]
            ^ self.fingerprints[h2 as usize])
    }
    fn geth0h1h2(&self, k: u64) -> Hashes {
        let hash = mixsplit(k, self.seed);
        let r0 = hash as u32;
        let r1 = rotl64(hash, 21) as u32;
        let r2 = rotl64(hash, 42) as u32;

        Hashes::new(
            hash,
            reduce(r0, self.block_length),
            reduce(r1, self.block_length),
            reduce(r2, self.block_length),
        )
    }

    fn geth0(&self, hash: u64) -> u32 {
        let r0 = hash as u32;
        reduce(r0, self.block_length)
    }

    fn geth1(&self, hash: u64) -> u32 {
        let r1 = rotl64(hash, 21) as u32;
        reduce(r1, self.block_length)
    }

    fn geth2(&self, hash: u64) -> u32 {
        let r2 = rotl64(hash, 42) as u32;
        reduce(r2, self.block_length)
    }
}

#[derive(Debug, Clone)]
struct XorSet {
    xormask: u64,
    count: u32,
}

impl XorSet {
    pub fn new(xormask: u64, count: u32) -> Self {
        XorSet { xormask, count }
    }
}

#[derive(Debug)]
struct Hashes {
    h: u64,
    h0: u32,
    h1: u32,
    h2: u32,
}

impl Hashes {
    pub fn new(h: u64, h0: u32, h1: u32, h2: u32) -> Self {
        Hashes { h, h0, h1, h2 }
    }
}

#[derive(Copy, Clone)]
struct KeyIndex {
    hash: u64,
    index: u32,
}

impl KeyIndex {
    pub fn new(hash: u64, index: u32) -> Self {
        KeyIndex { hash, index }
    }
}

fn murmur64(mut h: u64) -> u64 {
    h ^= h >> 33;
    h = h.wrapping_mul(0xff51_afd7_ed55_8ccd);
    h ^= h >> 33;
    h = h.wrapping_mul(0xc4ce_b9fe_1a85_ec53);
    h ^= h >> 33;
    h
}

// returns random number, modifies the seed
fn splitmix64(seed: &mut u64) -> u64 {
    *seed = (*seed).wrapping_add(0x9e37_79b9_7f4a_7c15); // warning
    let mut z = *seed;
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^ (z >> 31)
}

fn mixsplit(key: u64, seed: u64) -> u64 {
    murmur64(key + seed)
}

fn rotl64(n: u64, c: i64) -> u64 {
    (n << (c & 63)) | (n >> ((-c) & 63))
}

fn reduce(hash: u32, n: u32) -> u32 {
    // http://lemire.me/blog/2016/06/27/a-fast-alternative-to-the-modulo-reduction/
    let h = hash as u64;
    ((h.wrapping_mul(n as u64)) >> 32) as u32
}

fn fingerprint(hash: u64) -> u64 {
    hash ^ (hash >> 32)
}
