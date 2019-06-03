use rand::prelude::*;
use sha2::{Sha256, Digest};
use crate::memutil::{self, ProtectedBinary};

/// Contains the Globals and Singletons for an open database.
pub struct Context {
    pub crypto_random: CryptoRandom,
}

impl Context {
    pub fn new() -> Context {
        Context {
            crypto_random: CryptoRandom::new(),
        }
    }
}

pub struct CryptoRandom {
    entropy_pool: ProtectedBinary,
    counter: u64,
    pub generated_bytes_count: u64,
}

impl CryptoRandom {
    pub fn new() -> CryptoRandom {
        let mut rng = rand::thread_rng();
        let mut entropy_data = [0u8; 64];
        rng.fill(&mut entropy_data);

        debug_println!("context starting entropy: {}", memutil::to_hex_string(&entropy_data));

        let crypto_random = CryptoRandom {
            entropy_pool: ProtectedBinary::copy_slice(&entropy_data),
            counter: 0,
            generated_bytes_count: 0,
        };

        memutil::write_volatile(&mut entropy_data, 0);

        crypto_random
    }

    pub fn add_entropy(&mut self, entropy: &[u8]) {
        debug_println!("old entropy: {}", memutil::to_hex_string(ProtectedBinary::get(&self.entropy_pool)));
        if entropy.len() > 64 {
            let mut hasher = Sha256::new();
            hasher.input(entropy);
            let entropy = hasher.result();

            let mut new_entropy = ProtectedBinary::new(self.entropy_pool.len() + entropy.len());
            ProtectedBinary::copy_into(&mut new_entropy, 0, &self.entropy_pool);
            ProtectedBinary::copy_into(&mut new_entropy, self.entropy_pool.len(), &entropy);

            let mut hasher = Sha256::new();
            hasher.input(&self.entropy_pool);
            self.entropy_pool = ProtectedBinary::copy_slice(&hasher.result());
        } else {
            let mut new_entropy = ProtectedBinary::new(self.entropy_pool.len() + entropy.len());
            ProtectedBinary::copy_into(&mut new_entropy, 0, &self.entropy_pool);
            ProtectedBinary::copy_into(&mut new_entropy, self.entropy_pool.len(), entropy);

            let mut hasher = Sha256::new();
            hasher.input(&self.entropy_pool);
            self.entropy_pool = ProtectedBinary::copy_slice(&hasher.result());
        }
        debug_println!("new entropy: {}", memutil::to_hex_string(ProtectedBinary::get(&self.entropy_pool)));
    }

    pub fn get_csp_random(&self) -> [u8; 32] {
        let mut rng = rand::thread_rng();
        let mut buf = [0u8; 32];
        rng.fill(&mut buf);
        buf
    }

    pub fn generate_random_256(&mut self) -> [u8; 32] {
        self.counter = self.counter.wrapping_add(0x74D8B29E4D38E161);
        let mut counter = memutil::u64_to_bytes(self.counter);
        let mut csp = self.get_csp_random();
        let data: &[u8] = &self.entropy_pool;

        // @TODO use a smallvec with a size of 104 here instead.
        let mut cmp = Vec::with_capacity(counter.len() + csp.len() + data.len());
        cmp.extend_from_slice(data);
        cmp.extend_from_slice(&counter);
        cmp.extend_from_slice(data);

        memutil::zero_slice(&mut counter);
        memutil::zero_slice(&mut csp);

        self.generated_bytes_count += 32;

        let mut out = [0u8; 32];
        let mut hasher = Sha256::new();
        hasher.input(&cmp);
        out.copy_from_slice(&hasher.result());

        out
    }

    /// Get a number of cryptographically strong random bytes.
    pub fn get_random_bytes(&mut self, buf: &mut [u8]) {
        if buf.len() == 0 { return }

        let len = buf.len();
        let mut rem = buf.len();
        while rem > 0 {
            let random256 = self.generate_random_256();

            let dst_start = len - rem;
            let dst_end = std::cmp::min(dst_start + rem, dst_start + random256.len());
            let src_end = std::cmp::min(rem, random256.len());
            (&mut buf[dst_start..dst_end]).copy_from_slice(&random256[0..src_end]);

            rem -= src_end;
        }
    }

    /// @TODO not sure what this one does reall as of now. Doesn't seem necessary.
    pub fn new_weak_random() {
        unimplemented!("new_weak_random");
    }
}
