///! Crypto Random Stream

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

pub struct CryptoRandomStream {
    // @TODO
}
