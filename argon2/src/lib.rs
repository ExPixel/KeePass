//! Thin wrapper for the Argon2 C library.
//! All public argon2 functions are mapped to functions with the `argon2` prefix
//! and any leftover underscores after the prefix removed.
//! e.g. `argon2_ctx` -> `ctx` and `argon2i_ctx` -> `i_ctx`

#[allow(bad_style, dead_code)]
mod sys;
mod types;

use std::convert::TryInto;
use std::ffi::CStr;
use types::{opt_slice_ptr_mut, opt_slice_len, opt_slice_ptr};

pub use self::types::*;

/// Function that gives the string representation of an argon2 Variant.
/// If the `uppercase` parameter is true, the name of the variant is returned with the first letter
/// uppercased.
pub fn type2string(variant: Variant, uppercase: bool) -> &'static str {
    unsafe {
        let uppercase_i = if uppercase { 1 } else { 0 };
        let str_ptr = sys::argon2_type2string(variant.to_c(), uppercase_i);
        assert!(!str_ptr.is_null(), "null variant name.");
        let str_cstr = CStr::from_ptr(str_ptr);
        str_cstr.to_str().expect("Variant name is not valid UTF-8")
    }
}

/// Function that performs memory-hard hashing with certain degree of parallelism.
pub fn ctx<C: TryInto<sys::Argon2_Context, Error = self::Error>>(context: C, variant: Variant) -> Result<(), Error> {
    unsafe {
        Error::check_code(sys::argon2_ctx(&mut context.try_into()?, variant.to_c()) as _)
    }
}

/// Argon2d: Version of Argon2 that picks memory blocks depending on the password and salt. Only
/// for side-channel-free environment!!
pub fn d_ctx<C: TryInto<sys::Argon2_Context, Error = self::Error>>(context: C) -> Result<(), Error> {
    unsafe {
        Error::check_code(sys::argon2d_ctx(&mut context.try_into()?))
    }
}

/// Argon2i: Version of Argon2 that picks memory blocks
/// independent on the password and salt. Good for side-channels,
/// but worse with respect to tradeoff attacks if only one pass is used.
pub fn i_ctx<C: TryInto<sys::Argon2_Context, Error = self::Error>>(context: C) -> Result<(), Error> {
    unsafe {
        Error::check_code(sys::argon2i_ctx(&mut context.try_into()?))
    }
}

/// Argon2id: Version of Argon2 where the first half-pass over memory is
/// password-independent, the rest are password-dependent (on the password and
/// salt). OK against side channels (they reduce to 1/2-pass Argon2i), and
/// better with respect to tradeoff attacks (similar to Argon2d).
pub fn id_ctx<C: TryInto<sys::Argon2_Context, Error = self::Error>>(context: C) -> Result<(), Error> {
    unsafe {
        Error::check_code(sys::argon2id_ctx(&mut context.try_into()?))
    }
}

/// Hashes a password with Argon2i, producing an encoded (string) hash.
///
/// # Parameters
/// - `t_cost`: Number of iterations
/// - `m_cost`: Sets memory usage to m_cost kibibytes
/// - `parallelism`: Number of threads and compute lanes
/// - `pwd`: Slice containing the password.
/// - `salt`: Slice containing the salt.
/// - `hashlen`: Desired length of the hash in bytes.
/// - `encoded`: Buffer where to write the encoded hash.
///
/// # Notes
///
/// - The different parallelism levels will give different results.
pub fn i_hash_encoded(
    t_cost: u32,
    m_cost: u32,
    parallelism: u32,
    pwd: Option<&[u8]>,
    salt: Option<&[u8]>,
    hashlen: usize,
    encoded: &mut [u8]) -> Result<(), Error> {
    unsafe {
        Error::check_code(
            sys::argon2i_hash_encoded(
                t_cost, m_cost, parallelism,
                opt_slice_ptr(&pwd) as _,
                opt_slice_len(&pwd),
                opt_slice_ptr(&salt) as _,
                opt_slice_len(&salt),
                hashlen,
                encoded.as_mut_ptr() as _,
                encoded.len(),
            )
        )
    }
}

/// Hashes a password with Argon2i, producing a raw hash.
///
/// # Parameters
/// - `t_cost`: Number of iterations
/// - `m_cost`: Sets memory usage to m_cost kibibytes
/// - `parallelism`: Number of threads and compute lanes
/// - `pwd`: Slice containing the password.
/// - `salt`: Slice containing the salt.
/// - `hash`: Buffer where to write the raw hash.
///
/// # Notes
///
/// - The different parallelism levels will give different results.
pub fn i_hash_raw(
    t_cost: u32,
    m_cost: u32,
    parallelism: u32,
    pwd: Option<&[u8]>,
    salt: Option<&[u8]>,
    hash: &mut [u8]) -> Result<(), Error> {
    unsafe {
        Error::check_code(
            sys::argon2i_hash_raw(
                t_cost, m_cost, parallelism,
                opt_slice_ptr(&pwd) as _,
                opt_slice_len(&pwd),
                opt_slice_ptr(&salt) as _,
                opt_slice_len(&salt),
                hash.as_mut_ptr() as _,
                hash.len(),
            )
        )
    }
}

/// Hashes a password with Argon2d, producing an encoded (string) hash.
///
/// # Parameters
/// - `t_cost`: Number of iterations
/// - `m_cost`: Sets memory usage to m_cost kibibytes
/// - `parallelism`: Number of threads and compute lanes
/// - `pwd`: Slice containing the password.
/// - `salt`: Slice containing the salt.
/// - `hashlen`: Desired length of the hash in bytes.
/// - `encoded`: Buffer where to write the encoded hash.
///
/// # Notes
///
/// - The different parallelism levels will give different results.
pub fn d_hash_encoded(
    t_cost: u32,
    m_cost: u32,
    parallelism: u32,
    pwd: Option<&[u8]>,
    salt: Option<&[u8]>,
    hashlen: usize,
    encoded: &mut [u8]) -> Result<(), Error> {
    unsafe {
        Error::check_code(
            sys::argon2d_hash_encoded(
                t_cost, m_cost, parallelism,
                opt_slice_ptr(&pwd) as _,
                opt_slice_len(&pwd),
                opt_slice_ptr(&salt) as _,
                opt_slice_len(&salt),
                hashlen,
                encoded.as_mut_ptr() as _,
                encoded.len(),
            )
        )
    }
}

/// Hashes a password with Argon2d, producing a raw hash.
///
/// # Parameters
/// - `t_cost`: Number of iterations
/// - `m_cost`: Sets memory usage to m_cost kibibytes
/// - `parallelism`: Number of threads and compute lanes
/// - `pwd`: Slice containing the password.
/// - `salt`: Slice containing the salt.
/// - `hash`: Buffer where to write the raw hash.
///
/// # Notes
///
/// - The different parallelism levels will give different results.
pub fn d_hash_raw(
    t_cost: u32,
    m_cost: u32,
    parallelism: u32,
    pwd: Option<&[u8]>,
    salt: Option<&[u8]>,
    hash: &mut [u8]) -> Result<(), Error> {
    unsafe {
        Error::check_code(
            sys::argon2d_hash_raw(
                t_cost, m_cost, parallelism,
                opt_slice_ptr(&pwd) as _,
                opt_slice_len(&pwd),
                opt_slice_ptr(&salt) as _,
                opt_slice_len(&salt),
                hash.as_mut_ptr() as _,
                hash.len(),
            )
        )
    }
}

/// Hashes a password with Argon2id, producing an encoded (string) hash.
///
/// # Parameters
/// - `t_cost`: Number of iterations
/// - `m_cost`: Sets memory usage to m_cost kibibytes
/// - `parallelism`: Number of threads and compute lanes
/// - `pwd`: Slice containing the password.
/// - `salt`: Slice containing the salt.
/// - `hashlen`: Desired length of the hash in bytes.
/// - `encoded`: Buffer where to write the encoded hash.
///
/// # Notes
///
/// - The different parallelism levels will give different results.
pub fn id_hash_encoded(
    t_cost: u32,
    m_cost: u32,
    parallelism: u32,
    pwd: Option<&[u8]>,
    salt: Option<&[u8]>,
    hashlen: usize,
    encoded: &mut [u8]) -> Result<(), Error> {
    unsafe {
        Error::check_code(
            sys::argon2id_hash_encoded(
                t_cost, m_cost, parallelism,
                opt_slice_ptr(&pwd) as _,
                opt_slice_len(&pwd),
                opt_slice_ptr(&salt) as _,
                opt_slice_len(&salt),
                hashlen,
                encoded.as_mut_ptr() as _,
                encoded.len(),
            )
        )
    }
}

/// Hashes a password with Argon2id, producing a raw hash.
///
/// # Parameters
/// - `t_cost`: Number of iterations
/// - `m_cost`: Sets memory usage to m_cost kibibytes
/// - `parallelism`: Number of threads and compute lanes
/// - `pwd`: Slice containing the password.
/// - `salt`: Slice containing the salt.
/// - `hash`: Buffer where to write the raw hash.
///
/// # Notes
///
/// - The different parallelism levels will give different results.
pub fn id_hash_raw(
    t_cost: u32,
    m_cost: u32,
    parallelism: u32,
    pwd: Option<&[u8]>,
    salt: Option<&[u8]>,
    hash: &mut [u8]) -> Result<(), Error> {
    unsafe {
        Error::check_code(
            sys::argon2id_hash_raw(
                t_cost, m_cost, parallelism,
                opt_slice_ptr(&pwd) as _,
                opt_slice_len(&pwd),
                opt_slice_ptr(&salt) as _,
                opt_slice_len(&salt),
                hash.as_mut_ptr() as _,
                hash.len(),
            )
        )
    }
}

/// Generic Argon2 hash function.
///
/// # Parameters
/// - `t_cost`: Number of iterations
/// - `m_cost`: Sets memory usage to m_cost kibibytes
/// - `parallelism`: Number of threads and compute lanes
/// - `pwd`: Slice containing the password.
/// - `salt`: Slice containing the salt.
/// - `hash`: Buffer where to write the raw hash.
/// - `encoded`: Buffer where to write the encoded hash (as a string).
/// - `variant`: The variant (type) of Argon2 to use.
/// - `version`: The version of the Argon2 algorithm to use.
///
/// # Notes
///
/// - The different parallelism levels will give different results.
pub fn hash(
    t_cost: u32,
    m_cost: u32,
    parallelism: u32,
    pwd: Option<&[u8]>,
    salt: Option<&[u8]>,
    mut hash: Option<&mut [u8]>,
    mut encoded: Option<&mut [u8]>,
    variant: Variant,
    version: Version) -> Result<(), Error> {
    unsafe {
        Error::check_code(
            sys::argon2_hash(
                t_cost, m_cost, parallelism,
                opt_slice_ptr(&pwd) as _,
                opt_slice_len(&pwd),
                opt_slice_ptr(&salt) as _,
                opt_slice_len(&salt),
                opt_slice_ptr_mut(&mut hash) as _,
                opt_slice_len(&hash),
                opt_slice_ptr_mut(&mut encoded) as _,
                opt_slice_len(&encoded),
                variant.to_c() as _,
                version.to_c() as _,
            )
        )
    }
}

/// Verifies a password against an encoded string using Argon2i.
///
/// # Parameters
/// - `encoded`: String encoding parameters, salt, hash.
/// - `pwd`: Slice containing password.
pub fn i_verify(encoded: &CStr, pwd: Option<&[u8]>) -> Result<(), Error> {
    unsafe {
        Error::check_code(
            sys::argon2i_verify(
                encoded.as_ptr() as _,
                opt_slice_ptr(&pwd) as _,
                opt_slice_len(&pwd),
            )
        )
    }
}

/// Verifies a password against an encoded string using Argon2d.
///
/// # Parameters
/// - `encoded`: String encoding parameters, salt, hash.
/// - `pwd`: Slice containing password.
pub fn d_verify(encoded: &CStr, pwd: Option<&[u8]>) -> Result<(), Error> {
    unsafe {
        Error::check_code(
            sys::argon2d_verify(
                encoded.as_ptr() as _,
                opt_slice_ptr(&pwd) as _,
                opt_slice_len(&pwd),
            )
        )
    }
}

/// Verifies a password against an encoded string using Argon2id.
///
/// # Parameters
/// - `encoded`: String encoding parameters, salt, hash.
/// - `pwd`: Slice containing password.
pub fn id_verify(encoded: &CStr, pwd: Option<&[u8]>) -> Result<(), Error> {
    unsafe {
        Error::check_code(
            sys::argon2id_verify(
                encoded.as_ptr() as _,
                opt_slice_ptr(&pwd) as _,
                opt_slice_len(&pwd),
            )
        )
    }
}

/// Verifies a password against an encoded string.
///
/// # Parameters
/// - `encoded`: String encoding parameters, salt, hash.
/// - `pwd`: Slice containing password.
pub fn verify(encoded: &CStr, pwd: Option<&[u8]>, variant: Variant) -> Result<(), Error> {
    unsafe {
        Error::check_code(
            sys::argon2_verify(
                encoded.as_ptr() as _,
                opt_slice_ptr(&pwd) as _,
                opt_slice_len(&pwd),
                variant.to_c() as _,
            )
        )
    }
}

/// Verify if a given password is correct for Argon2d hashing.
///
/// # Parameters
///
/// - `context`: The current Argon2 context.
/// - `hash`: The password hash to verify. The length of the hash must match the length of the out
/// parameter in context.
pub fn d_verify_ctx<C: TryInto<sys::Argon2_Context, Error = self::Error>>(context: C, hash: &[u8]) -> Result<(), Error> {

    let mut argon_context = context.try_into()?;
    if hash.len() as u32 != argon_context.outlen {
        return Err(Error::BadParam("hash.len"))
    }

    unsafe {
        Error::check_code(
            sys::argon2d_verify_ctx(
                &mut argon_context,
                hash.as_ptr() as _,
            )
        )
    }
}

/// Verify if a given password is correct for Argon2i hashing.
///
/// # Parameters
///
/// - `context`: The current Argon2 context.
/// - `hash`: The password hash to verify. The length of the hash must match the length of the out
/// parameter in context.
pub fn i_verify_ctx<C: TryInto<sys::Argon2_Context, Error = self::Error>>(context: C, hash: &[u8]) -> Result<(), Error> {

    let mut argon_context = context.try_into()?;
    if hash.len() as u32 != argon_context.outlen {
        return Err(Error::BadParam("hash.len"))
    }

    unsafe {
        Error::check_code(
            sys::argon2i_verify_ctx(
                &mut argon_context,
                hash.as_ptr() as _,
            )
        )
    }
}

/// Verify if a given password is correct for Argon2id hashing.
///
/// # Parameters
///
/// - `context`: The current Argon2 context.
/// - `hash`: The password hash to verify. The length of the hash must match the length of the out
/// parameter in context.
pub fn id_verify_ctx<C: TryInto<sys::Argon2_Context, Error = self::Error>>(context: C, hash: &[u8]) -> Result<(), Error> {

    let mut argon_context = context.try_into()?;
    if hash.len() as u32 != argon_context.outlen {
        return Err(Error::BadParam("hash.len"))
    }

    unsafe {
        Error::check_code(
            sys::argon2id_verify_ctx(
                &mut argon_context,
                hash.as_ptr() as _,
            )
        )
    }
}

/// Verify if a given password is correct for a given variant of Argon2 hashing.
///
/// # Parameters
///
/// - `context`: The current Argon2 context.
/// - `hash`: The password hash to verify. The length of the hash must match the length of the out
/// parameter in context.
pub fn verify_ctx<C: TryInto<sys::Argon2_Context, Error = self::Error>>(context: C, hash: &[u8], variant: Variant) -> Result<(), Error> {

    let mut argon_context = context.try_into()?;
    if hash.len() as u32 != argon_context.outlen {
        return Err(Error::BadParam("hash.len"))
    }

    unsafe {
        Error::check_code(
            sys::argon2_verify_ctx(
                &mut argon_context,
                hash.as_ptr() as _,
                variant.to_c() as _,
            )
        )
    }
}

/// Get the associated error message for a given error code.
pub fn error_message(code: ErrorCode) -> Option<&'static str> {
    unsafe {
        let str_ptr = sys::argon2_error_message(code.to_c());
        if str_ptr.is_null() {
            None
        } else {
            let str_cstr = CStr::from_ptr(str_ptr);
            Some(str_cstr.to_str().expect("Variant name is not valid UTF-8"))
        }
    }
}

/// Returns the encoded hash length for the given input parameters.
///
/// # Parameters
/// `t_cost`: Number of iterations.
/// `m_cost`: Memory usage in kibibytes.
/// `parallelism`: Number of threads; used to compute lanes.
/// `saltlen`: Salt size in bytes.
/// `hashlen`: Hash size in bytes.
/// `variant`: The Argon2 Variant that we want the encoded length for.
///
/// # Returns
///
/// The encoded hash length in bytes.
pub fn encodedlen(
    t_cost: u32,
    m_cost: u32,
    parallelism: u32,
    saltlen: u32,
    hashlen: u32,
    variant: Variant) -> usize {
    unsafe {
        sys::argon2_encodedlen(t_cost, m_cost, parallelism, saltlen, hashlen, variant.to_c() as _)
    }
}

/// Converts a slice of bytes to a CStr.
/// Unlike CStr::from_bytes_with_nul this will stop at the first
/// null byte instead of returning an error for interior null bytes.
/// This will return an error if there are no null bytes at all.
pub fn c_str(bytes: &[u8]) -> Result<&CStr, Error> {
    for (idx, b) in bytes.iter().enumerate() {
        if *b == 0 {
            return Ok(CStr::from_bytes_with_nul(&bytes[0..(idx + 1)]).expect("Failed CStr conversion."));
        }
    }
    Err(Error::BadParam("bytes"))
}

/// Converts a slice of bytes to a CStr much like `c_str` except this will allocate a C string for
/// you instead with a terminating null byte if one cannot be found inside of the given byte
/// string.
pub fn c_str_cow<'a>(bytes: &'a [u8]) -> std::borrow::Cow<'a, CStr> {
    for (idx, b) in bytes.iter().enumerate() {
        if *b == 0 {
            return std::borrow::Cow::Borrowed(
                CStr::from_bytes_with_nul(&bytes[0..(idx + 1)])
                .expect("Failed CStr conversion.")
            );
        }
    }

    std::borrow::Cow::Owned(
        std::ffi::CString::new(bytes).expect("Failed to create CString.")
    )
}

#[cfg(test)]
mod test {
    use super::*;

    /// Make sure that all variants have names.
    #[test]
    fn test_variant_names() {
        assert_eq!("argon2i", type2string(Variant::I, false));
        assert_eq!("Argon2i", type2string(Variant::I, true));
        assert_eq!("argon2d", type2string(Variant::D, false));
        assert_eq!("Argon2d", type2string(Variant::D, true));
        assert_eq!("argon2id", type2string(Variant::ID, false));
        assert_eq!("Argon2id", type2string(Variant::ID, true));
    }

    fn hex_conv(bytes: &[u8], hex_dest: &mut [u8]) {
        const DIGITS: &[u8] = b"0123456789abcdef";
        for (idx, byte) in bytes.iter().enumerate() {
            hex_dest[(idx * 2)] = DIGITS[((*byte >> 4) as usize) & 0xF];
            hex_dest[(idx * 2) + 1] = DIGITS[(*byte as usize) & 0xF];
        }
    }

    fn str_conv(bytes: &[u8]) -> &str {
        std::str::from_utf8(bytes).expect("Bad UTF-8 conversion.")
    }

    fn tovec(a: &[u8]) -> Vec<u8> {
        let mut v = Vec::with_capacity(a.len());
        v.extend_from_slice(a);
        return v
    }

    fn hashtest_bytes(version: Version, t: u32, m: u32, p: u32, pwd: &mut [u8], salt: &mut [u8], hexref: &mut [u8], mcfref: &mut [u8], variant: Variant) {
        const OUTLEN: usize = 32;
        const ENCODED_LEN: usize = 108;

        let mut out = [0u8; OUTLEN];
        let mut hex_out = [0u8; OUTLEN * 2 + 4];
        let mut encoded = [0u8; ENCODED_LEN];

        println!("HASH TEST: $v={:?} t={}, m={}, p = {}, pass={}, salt={}",
                 version, t, m, p,
                 unsafe { std::str::from_utf8_unchecked(pwd) },
                 unsafe { std::str::from_utf8_unchecked(salt) },);

        hash(t, 1<<m, p, Some(pwd), Some(salt), Some(&mut out), Some(&mut encoded), variant, version).expect("Test hash failed.");
        hex_conv(&out, &mut hex_out);

        assert_eq!(str_conv(hexref), str_conv(&hex_out[0..(OUTLEN * 2)]));

        verify(
            c_str(&encoded).expect("bad C string."), Some(pwd), variant
        ).expect("Failed verify-1");

        verify(
            &c_str_cow(&mcfref), Some(pwd), variant
        ).expect("Failed verify-1");
    }

    fn hashtest(version: Version, t: u32, m: u32, p: u32, pwd: &str, salt: &str, hexref: &str, mcfref: &str, variant: Variant) {
        hashtest_bytes(
            version, t, m, p,
            &mut tovec(pwd.as_bytes()),
            &mut tovec(salt.as_bytes()),
            &mut tovec(hexref.as_bytes()),
            &mut tovec(mcfref.as_bytes()),
            variant);
    }

    macro_rules! check_error_code {
        ($Code:ident, $Value:expr) => {
            assert_eq!(Err(Error::Code(ErrorCode::$Code)), $Value)
        }
    }

    #[test]
    fn test_argon2i_0x10() {
        println!("Test Argon2i version number: 0x{:02X}", (Version::Version10).to_int());
        hashtest(Version::Version10, 2, 16, 1, "password", "somesalt",
             "f6c4db4a54e2a370627aff3db6176b94a2a209a62c8e36152711802f7b30c694",
             "$argon2i$m=65536,t=2,p=1$c29tZXNhbHQ$9sTbSlTio3Biev89thdrlKKiCaYsjjYVJxGAL3swxpQ",
             Variant::I);
        hashtest(Version::Version10, 2, 18, 1, "password", "somesalt",
                 "3e689aaa3d28a77cf2bc72a51ac53166761751182f1ee292e3f677a7da4c2467",
                 "$argon2i$m=262144,t=2,p=1$c29tZXNhbHQ$Pmiaqj0op3zyvHKlGsUxZnYXURgvHuKS4/Z3p9pMJGc",
                 Variant::I);
        hashtest(Version::Version10, 2, 8, 1, "password", "somesalt",
                 "fd4dd83d762c49bdeaf57c47bdcd0c2f1babf863fdeb490df63ede9975fccf06",
                 "$argon2i$m=256,t=2,p=1$c29tZXNhbHQ$/U3YPXYsSb3q9XxHvc0MLxur+GP960kN9j7emXX8zwY",
                 Variant::I);
        hashtest(Version::Version10, 2, 8, 2, "password", "somesalt",
                 "b6c11560a6a9d61eac706b79a2f97d68b4463aa3ad87e00c07e2b01e90c564fb",
                 "$argon2i$m=256,t=2,p=2$c29tZXNhbHQ$tsEVYKap1h6scGt5ovl9aLRGOqOth+AMB+KwHpDFZPs",
                 Variant::I);
        hashtest(Version::Version10, 1, 16, 1, "password", "somesalt",
                 "81630552b8f3b1f48cdb1992c4c678643d490b2b5eb4ff6c4b3438b5621724b2",
                 "$argon2i$m=65536,t=1,p=1$c29tZXNhbHQ$gWMFUrjzsfSM2xmSxMZ4ZD1JCytetP9sSzQ4tWIXJLI",
                 Variant::I);
        hashtest(Version::Version10, 4, 16, 1, "password", "somesalt",
                 "f212f01615e6eb5d74734dc3ef40ade2d51d052468d8c69440a3a1f2c1c2847b",
                 "$argon2i$m=65536,t=4,p=1$c29tZXNhbHQ$8hLwFhXm6110c03D70Ct4tUdBSRo2MaUQKOh8sHChHs",
                 Variant::I);
        hashtest(Version::Version10, 2, 16, 1, "differentpassword", "somesalt",
                 "e9c902074b6754531a3a0be519e5baf404b30ce69b3f01ac3bf21229960109a3",
                 "$argon2i$m=65536,t=2,p=1$c29tZXNhbHQ$6ckCB0tnVFMaOgvlGeW69ASzDOabPwGsO/ISKZYBCaM",
                 Variant::I);
        hashtest(Version::Version10, 2, 16, 1, "password", "diffsalt",
                 "79a103b90fe8aef8570cb31fc8b22259778916f8336b7bdac3892569d4f1c497",
                 "$argon2i$m=65536,t=2,p=1$ZGlmZnNhbHQ$eaEDuQ/orvhXDLMfyLIiWXeJFvgza3vaw4kladTxxJc",
                 Variant::I);

        check_error_code!(DecodingFail, verify(&c_str_cow(b"$argon2i$m=65536,t=2,p=1c29tZXNhbHQ$9sTbSlTio3Biev89thdrlKKiCaYsjjYVJxGAL3swxpQ"),
               Some(b"password"), Variant::I));
        check_error_code!(DecodingFail, verify(&c_str_cow(b"$argon2i$m=65536,t=2,p=1$c29tZXNhbHQ9sTbSlTio3Biev89thdrlKKiCaYsjjYVJxGAL3swxpQ"),
               Some(b"password"), Variant::I));
        check_error_code!(SaltTooShort, verify(&c_str_cow(b"$argon2i$m=65536,t=2,p=1$$9sTbSlTio3Biev89thdrlKKiCaYsjjYVJxGAL3swxpQ"),
               Some(b"password"), Variant::I));
        check_error_code!(VerifyMismatch, verify(&c_str_cow(b"$argon2i$m=65536,t=2,p=1$c29tZXNhbHQ$b2G3seW+uPzerwQQC+/E1K50CLLO7YXy0JRcaTuswRo"),
               Some(b"password"), Variant::I));
    }

    #[test]
    #[ignore]
    fn test_argon2i_0x10_large_ram() {
        hashtest(Version::Version10, 2, 20, 1, "password", "somesalt",
                "9690ec55d28d3ed32562f2e73ea62b02b018757643a2ae6e79528459de8106e9",
                "$argon2i$m=1048576,t=2,p=1$c29tZXNhbHQ$lpDsVdKNPtMlYvLnPqYrArAYdXZDoq5ueVKEWd6BBuk",
                Variant::I);
    }
}
