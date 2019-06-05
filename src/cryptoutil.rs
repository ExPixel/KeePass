use crate::memutil;
use sha2::{Sha256, Sha512, Digest as _};
use hmac::{Hmac, Mac};

type HmacSha256 = Hmac<Sha256>;

/// Create a cryptographic filling `dst` from `src`.
pub fn resize_key(src: &[u8], dst: &mut [u8]) {
    if dst.len() == 0 { return }

    if dst.len() <= 32 {
        let mut hasher = Sha256::new();
        hasher.input(&src);
        dst.copy_from_slice(&hasher.result()[0..dst.len()]);
        return;
    }

    let mut hasher = Sha512::new();
    hasher.input(&src);
    let hash_src = hasher.result();

    if dst.len() <= hash_src.len() {
        dst.copy_from_slice(&hash_src[0..dst.len()]);
    } else {
        let mut idx = 0usize;
        let mut r = 0u64;
        while idx < dst.len() {
            let mut mac = HmacSha256::new_varkey(&hash_src).expect("Failed to create HmacSha256.");
            mac.input(&memutil::u64_to_bytes(r));
            let part = mac.result().code();
            let copylen = std::cmp::min(part.len(), dst.len() - idx);
            (&mut dst[idx..copylen]).copy_from_slice(&part[0..copylen]);
            idx += copylen;
            r += 1;
        }
    }
}
