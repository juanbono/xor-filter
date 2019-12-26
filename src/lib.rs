mod util;
use util::*;

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
        let mut capacity = 32 + (1.23 * size as f64).ceil() as u32;
        capacity = capacity / 3 * 3; // round it down to a multiple of 3
        let mut rngcounter = 1;
        let mut fingerprints = Vec::new();
        fingerprints.resize(capacity as usize, 0);

        let mut filter = Xor8 {
            block_length: capacity / 3,
            fingerprints,
            seed: splitmix64(&mut rngcounter),
        };

        let block_length = filter.block_length as usize;
        let mut q0: Vec<KeyIndex> = vec![Default::default(); block_length];
        let mut q1: Vec<KeyIndex> = vec![Default::default(); block_length];
        let mut q2: Vec<KeyIndex> = vec![Default::default(); block_length];
        
        let mut sets0: Vec<XorSet> = vec![Default::default(); block_length];
        let mut sets1: Vec<XorSet> = vec![Default::default(); block_length];
        let mut sets2: Vec<XorSet> = vec![Default::default(); block_length];

        let mut stack: Vec<KeyIndex> = vec![Default::default(); size];

        loop {
            for k in keys.iter() {
                let key = *k;
                let hs = filter.hashes(key);
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
                    let index = keyindex_var.index as usize;
                    if sets0[index].count == 0 {
                        continue; // not actually possible after the initial scan
                    }
                    let hash = keyindex_var.hash;
                    let h1 = filter.h1(hash);
                    let h2 = filter.h2(hash);
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
                    let index = keyindex_var.index as usize;
                    if sets1[index].count == 0 {
                        continue;
                    }
                    let hash = keyindex_var.hash;
                    let h0 = filter.h0(hash) as usize;
                    let h2 = filter.h2(hash) as usize;
                    keyindex_var.index = filter.block_length;
                    stack[stack_size] = keyindex_var;
                    stack_size += 1;
                    sets0[h0].xormask ^= hash;
                    sets0[h0].count -= 1;
                    if sets0[h0 as usize].count == 1 {
                        q0[q0_size].index = h0 as u32;
                        q0[q0_size].hash = sets0[h0].xormask;
                        q0_size += 1;
                    }
                    sets2[h2].xormask ^= hash;
                    sets2[h2].count -= 1;
                    if sets2[h2].count == 1 {
                        q2[q2_size].index = h2 as u32;
                        q2[q2_size].hash = sets2[h2].xormask;
                        q2_size += 1;
                    }
                }

                while q2_size > 0 {
                    q2_size -= 1;
                    let mut keyindex_var = q2[q2_size];
                    let index = keyindex_var.index as usize;
                    if sets2[index].count == 0 {
                        continue;
                    }
                    let hash = keyindex_var.hash;
                    let h0 = filter.h0(hash) as usize;
                    let h1 = filter.h1(hash) as usize;
                    keyindex_var.index += 2 * filter.block_length;

                    stack[stack_size] = keyindex_var;
                    stack_size += 1;
                    sets0[h0].xormask ^= hash;
                    sets0[h0].count -= 1;
                    if sets0[h0].count == 1 {
                        q0[q0_size].index = h0 as u32;
                        q0[q0_size].hash = sets0[h0].xormask;
                        q0_size += 1;
                    }
                    sets1[h1].xormask ^= hash;
                    sets1[h1].count -= 1;
                    if sets1[h1].count == 1 {
                        q1[q1_size].index = h1 as u32;
                        q1[q1_size].hash = sets1[h1].xormask;
                        q1_size += 1;
                    }
                }
            }

            if stack_size == size {
                break; // success
            }

            sets0 = sets0.iter().map(|_| Default::default()).collect();
            sets1 = sets1.iter().map(|_| Default::default()).collect();
            sets2 = sets2.iter().map(|_| Default::default()).collect();
            filter.seed = splitmix64(&mut rngcounter);
        }

        let mut stack_size = size;

        while stack_size > 0 {
            stack_size -= 1;
            let ki = stack[stack_size];
            let mut val = fingerprint(ki.hash) as u8;
            if ki.index < filter.block_length {
                val ^= filter.fingerprints[(filter.h1(ki.hash) + filter.block_length) as usize]
                    ^ filter.fingerprints[(filter.h2(ki.hash) + 2 * filter.block_length) as usize];
            } else if ki.index < 2 * filter.block_length {
                val ^= filter.fingerprints[filter.h0(ki.hash) as usize]
                    ^ filter.fingerprints[(filter.h2(ki.hash) + 2 * filter.block_length) as usize];
            } else {
                val ^= filter.fingerprints[filter.h0(ki.hash) as usize]
                    ^ filter.fingerprints[(filter.h1(ki.hash) + filter.block_length) as usize];
            }
            filter.fingerprints[ki.index as usize] = val;
        }
        filter
    }

    /// tells you whether the key is likely part of the set
    pub fn contains(&self, key: u64) -> bool {
        let hash = mixsplit(key, self.seed);
        let f = fingerprint(hash) as u8;
        let h0 = self.h0(hash) as usize;
        let h1 = (self.h1(hash) + self.block_length) as usize;
        let h2 = (self.h2(hash) + 2 * self.block_length) as usize;
        f == (self.fingerprints[h0] ^ self.fingerprints[h1] ^ self.fingerprints[h2])
    }

    fn hashes(&self, k: u64) -> Hashes {
        let hash = mixsplit(k, self.seed);
        Hashes::new(hash, self.h0(hash), self.h1(hash), self.h2(hash))
    }

    fn h0(&self, hash: u64) -> u32 {
        let r0 = hash as u32;
        reduce(r0, self.block_length)
    }

    fn h1(&self, hash: u64) -> u32 {
        let r1 = rotl64(hash, 21) as u32;
        reduce(r1, self.block_length)
    }

    fn h2(&self, hash: u64) -> u32 {
        let r2 = rotl64(hash, 42) as u32;
        reduce(r2, self.block_length)
    }
}

#[derive(Clone, Default)]
struct XorSet {
    xormask: u64,
    count: u32,
}

#[derive(Copy, Clone, Default)]
struct KeyIndex {
    hash: u64,
    index: u32,
}

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
