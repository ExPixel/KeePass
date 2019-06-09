use super::cipher::CtrBlockCipher as _;
use super::cipher::chacha20::{ChaCha20, ChaCha20Ctr};
use super::cipher::salsa20::{Salsa20, Salsa20Ctr};

/// Algorithms supported by `CryptoRandomStream`.
#[repr(u32)]
#[derive(Copy, Clone, PartialEq, Eq)]
pub enum CrsAlgorithm {
    /// Not supported.
    None = 0,

    /// A variant of the ARCFour algorithm (RC4 incompatible).
    /// Insecure; for backward compatibility only.
    ArcFourVariant = 1,

    /// Salsa20 stream cipher algorithm.
    Salsa20 = 2,

    /// ChaCha20 stream cipher algorithm.
    ChaCha20 = 3,
}

impl CrsAlgorithm {
    pub fn from_int(n: u32) -> Option<CrsAlgorithm> {
        match n {
            0 => Some(CrsAlgorithm::None),
            1 => Some(CrsAlgorithm::ArcFourVariant),
            2 => Some(CrsAlgorithm::Salsa20),
            3 => Some(CrsAlgorithm::ChaCha20),
            _ => None,
        }
    }

    pub fn to_int(this: CrsAlgorithm) -> u32 {
        match this {
            CrsAlgorithm::None => 0,
            CrsAlgorithm::ArcFourVariant => 1,
            CrsAlgorithm::Salsa20 => 2,
            CrsAlgorithm::ChaCha20 => 3,
        }
    }
}

pub enum CryptoRandomStream {
    Salsa20(Salsa20Ctr),
    ChaCha20(ChaCha20Ctr),
    ArcFourVariant {
        i: u8,
        j: u8,
        state: [u8; 256]
    },
}

impl CryptoRandomStream {
    pub fn new(algorithm: CrsAlgorithm, key: &[u8]) -> CryptoRandomStream {
        use sha2::{Sha256, Sha512, Digest as _};

        match algorithm {
            CrsAlgorithm::ChaCha20 => {
                let mut hasher = Sha512::new();
                hasher.input(key);
                let hash = &hasher.result()[0..];
                CryptoRandomStream::ChaCha20(ChaCha20::new_ctr(&hash[0..32], &hash[32..44]))
            },
            CrsAlgorithm::Salsa20 => {
                const SALSA20_CRS_IV: [u8; 8] = [0xE8, 0x30, 0x09, 0x4B, 0x97, 0x20, 0x5D, 0x2A];

                let mut hasher = Sha256::new();
                hasher.input(key);
                let hash = &hasher.result()[0..];

                CryptoRandomStream::Salsa20(Salsa20::new_ctr(hash, &SALSA20_CRS_IV))
            },
            CrsAlgorithm::ArcFourVariant => {
                CryptoRandomStream::new_arc_four_variant(key)
            },
            CrsAlgorithm::None => {
                panic!("Unsupported CRS Algorithm.");
            },
        }
    }

    fn new_arc_four_variant(key: &[u8]) -> CryptoRandomStream {
        let mut state = [0u8; 256];

        // state = [0, 1, 2, 3, ..., 255]
        state.iter_mut().enumerate().for_each(|(idx, elem)| *elem = idx as u8);

        let mut j = 0u8;
        let mut key_idx = 0;

        for w in 0..state.len() {
            j = state[w].wrapping_add(key[key_idx]);
            state.swap(0, j as usize);
            key_idx += 1;
            if key_idx > key.len() {
                key_idx = 0;
            }
        }

        let mut crs = CryptoRandomStream::ArcFourVariant {
            state: state,
            i: 0,
            j: 0,
        };

        let mut chunk = [0u8; 32];
        for _ in 0..16 {
            crs.get_random_bytes(&mut chunk);
        }
        // ^ Do this 512 times to increase security or whatever...


        return crs;
    }

    pub fn get_random_bytes(&mut self, dest: &mut [u8]) {
        if dest.len() == 0 { return }

        match *self {
            CryptoRandomStream::ChaCha20(ref mut chacha) => {
                chacha.apply_keystream(dest)
            },

            CryptoRandomStream::Salsa20(ref mut salsa) => {
                salsa.apply_keystream(dest)
            },

            CryptoRandomStream::ArcFourVariant {
                ref mut state,
                ref mut i,
                ref mut j,
            } => {
                for w in 0..dest.len() {
                    *i = (*i).wrapping_add(1);
                    *j = (*j).wrapping_add(state[*i as usize]);
                    state.swap(*i as usize, *j as usize);
                    dest[w] = state[*i as usize].wrapping_add(state[*j as usize]);
                }
            },
        }
    }

    pub fn get_random_u64(&mut self) -> u64 {
        let mut buf = [0u8; 8];
        self.get_random_bytes(&mut buf);
        crate::memutil::bytes_to_u64(&buf)
    }

    /// Get a random u64 from 0 to `max`
    pub fn get_random_u64_max(&mut self, max: u64) {
        assert!(max != 0, "`max` cannot be 0.");

        let mut ugen;
        let mut urem;
        loop {
            ugen = self.get_random_u64();
            urem = ugen % max;
            if (ugen.wrapping_sub(urem)) <= (std::u64::MAX - (max - 1)) {
                break;
            }
        }
    }
}
