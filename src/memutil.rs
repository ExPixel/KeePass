use crate::error::Error;

pub fn hex_to_bytes(hex: &[u8]) -> Vec<u8> {
    assert!(hex.len() % 2 == 0);
    let mut dest = Vec::new();

    for byte in hex.chunks(2) {
        dest.push(hex_pair_to_byte((byte[0], byte[1])));
    }

    return dest;
}

pub fn hex_pair_to_byte(pair: (u8, u8)) -> u8 {
    let hi = hex_to_nibble(pair.0);
    let lo = hex_to_nibble(pair.1);

    return (hi << 4) | lo;

    fn hex_to_nibble(hex: u8) -> u8 {
        match hex {
            b'0'...b'9' => hex - b'0',
            b'A'...b'F' => hex - b'A' + 10,
            b'a'...b'f' => hex - b'a' + 10,
            _ => panic!("hex digit out of range."),
        }
    }
}

/// XOR dst with src (overwrites the values in dst).
/// If dst is not the same size as src, the larger slice
/// will be truncated.
pub fn xor_slices(mut dst: &mut [u8], mut src: &[u8]) {
    if dst.len() > src.len() {
        dst = &mut dst[0..src.len()]
    } else if src.len() > dst.len() {
        src = &src[0..dst.len()]
    }

    for (idx, elem) in dst.iter_mut().enumerate() {
        *elem = *elem ^ *(unsafe { src.get_unchecked(idx) });
    }
}

pub fn to_hex_char_pair(n: u8) -> (u8, u8) {
    static HEX_CHARS: [u8; 16] = [
            b'0', b'1', b'2', b'3', b'4', b'5', b'6', b'7',
            b'8', b'9', b'A', b'B', b'C', b'D', b'E', b'F'
    ];

    (HEX_CHARS[(n & 0xF) as usize], HEX_CHARS[((n >> 4) & 0xF) as usize])
}

pub fn write_hex_bytes(bytes: &[u8], dest: &mut Vec<u8>) {
    for b in bytes.iter() {
        let (lo, hi) = to_hex_char_pair(*b);
        dest.push(hi);
        dest.push(lo);
    }
}

pub fn write_hex_string(bytes: &[u8], dest: &mut String) {
    for b in bytes.iter() {
        let (lo, hi) = to_hex_char_pair(*b);
        dest.push(hi as char);
        dest.push(lo as char);
    }
}

pub fn to_hex_string(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    write_hex_string(bytes, &mut s);
    s
}

pub fn to_hex_into_slice(bytes: &[u8], dest: &mut [u8]) {
    debug_assert!(dest.len() >= bytes.len() * 2, "destination buffer is not large enough to store the hex representation of the source");
    let mut idx = 0;

    for b in bytes.iter() {
        let (lo, hi) = to_hex_char_pair(*b);
        dest[idx    ] = hi;
        dest[idx + 1] = lo;
        idx += 2;
    }
}

/// Turns a u16 into a byte array in little endian byte order.
#[inline]
pub fn u16_to_bytes(n: u16) -> [u8; 2] {
    [
        n as u8,
        (n >>  8) as u8,
    ]
}

/// Turns a u32 into a byte array in little endian byte order.
#[inline]
pub fn u32_to_bytes(n: u32) -> [u8; 4] {
    [
        n as u8,
        (n >>  8) as u8,
        (n >> 16) as u8,
        (n >> 24) as u8,
    ]
}

/// Turns a u64 into a byte array in little endian byte order.
#[inline]
pub fn u64_to_bytes(n: u64) -> [u8; 8] {
    [
        n as u8,
        (n >>  8) as u8,
        (n >> 16) as u8,
        (n >> 24) as u8,
        (n >> 32) as u8,
        (n >> 40) as u8,
        (n >> 48) as u8,
        (n >> 56) as u8,
    ]
}

/// Turns an i16 into a byte array in little endian byte order.
#[inline]
pub fn i16_to_bytes(n: i16) -> [u8; 2] {
    u16_to_bytes(n as u16)
}

/// Turns an i32 into a byte array in little endian byte order.
#[inline]
pub fn i32_to_bytes(n: i32) -> [u8; 4] {
    u32_to_bytes(n as u32)
}

/// Turns an i64 into a byte array in little endian byte order.
#[inline]
pub fn i64_to_bytes(n: i64) -> [u8; 8] {
    u64_to_bytes(n as u64)
}

/// Reads bytes into a u32 in little-endian order.
#[inline]
pub fn bytes_to_u32(bytes: &[u8]) -> u32 {
    debug_assert!(bytes.len() >= 4, "Cannot convert a buffer with a length less than 4 into a u32");
    (bytes[0] as u32) |
    ((bytes[1] as u32) <<  8 )|
    ((bytes[2] as u32) << 16 )|
    ((bytes[3] as u32) << 24 )
}

/// Reads bytes into a u64 in little-endian order.
#[inline]
pub fn bytes_to_u64(bytes: &[u8]) -> u64 {
    debug_assert!(bytes.len() >= 8, "Cannot convert a buffer with a length less than 4 into a u64");
    (bytes[0] as u64) |
    ((bytes[1] as u64) <<  8)|
    ((bytes[2] as u64) << 16)|
    ((bytes[3] as u64) << 24)|
    ((bytes[4] as u64) << 32)|
    ((bytes[5] as u64) << 40)|
    ((bytes[6] as u64) << 48)|
    ((bytes[7] as u64) << 56)
}

/// Reads bytes into an i64 in little-endian order.
#[inline]
pub fn bytes_to_i64(bytes: &[u8]) -> i64 {
    debug_assert!(bytes.len() >= 8, "Cannot convert a buffer with a length less than 4 into a i64");
    (bytes[0] as i64) |
    ((bytes[1] as i64) <<  8)|
    ((bytes[2] as i64) << 16)|
    ((bytes[3] as i64) << 24)|
    ((bytes[4] as i64) << 32)|
    ((bytes[5] as i64) << 40)|
    ((bytes[6] as i64) << 48)|
    ((bytes[7] as i64) << 56)
}

/// Reads bytes into a u32 in little-endian order.
#[inline]
pub fn bytes_to_u16(bytes: &[u8]) -> u16 {
    debug_assert!(bytes.len() >= 2, "Cannot convert a buffer with a length less than 2 into a u16");
    (bytes[0] as u16) | ((bytes[1] as u16) <<  8 )
}

/// Reads bytes into an i32 in little-endian order.
#[inline]
pub fn bytes_to_i32(bytes: &[u8]) -> i32 {
    bytes_to_u32(bytes) as i32
}

/// Reads bytes into an i16 in little-endian order.
#[inline]
pub fn bytes_to_i16(bytes: &[u8]) -> i16 {
    bytes_to_u16(bytes) as i16
}

/// Use fences to prevent accesses from being reordered before this point.
/// Not sure if this works but this is how zeroize implements this.
#[inline]
fn atomic_fence() {
    use std::sync::atomic;
    atomic::fence(atomic::Ordering::SeqCst);
    atomic::compiler_fence(atomic::Ordering::SeqCst);
}

// @TODO maybe I can speed this up by writing u32s or u64s where possible.
unsafe fn ptr_write_bytes_volatile<T: Sized>(dst: *mut T, val: u8, count: usize) {
    let dst_bytes: *mut u8 = std::mem::transmute(dst);
    let bytes_count = (count * std::mem::size_of::<T>()) as isize;
    for offset in 0..bytes_count {
        std::ptr::write_volatile(dst_bytes.offset(offset), val);
    }
    atomic_fence();
}

pub fn write_volatile<T: Sized>(dst: &mut [T], val: u8) {
    let count = dst.len();
    unsafe {
        ptr_write_bytes_volatile(dst.as_mut_ptr(), val, count);
    }
}

pub fn zero_slice<T: Sized>(dst: &mut [T]) {
    let count = dst.len();
    unsafe {
        ptr_write_bytes_volatile(dst.as_mut_ptr(), 0, count);
    }
}

pub fn zero_vec<T: Sized + Clone + Default>(dst: &mut Vec<T>) {
    dst.resize(dst.capacity(), T::default());
    zero_slice(&mut dst[0..]);
    dst.clear();
}

/// A string that has its memory zeroed when it is dropped.
/// #TODO In KeePass's implementation the string is stored encrypted in memory.
///       I'm not sure how useful that is since it's constantly being unencrypted anyway
///       so I'll leave the implementation like this for now.
#[derive(Clone, PartialEq, Eq)]
pub struct ProtectedString {
    inner: String,
}

impl ProtectedString {
    pub fn wrap(value: String) -> ProtectedString {
        ProtectedString {
            inner: value
        }
    }

    pub fn get(this: &ProtectedString) -> &String {
        &this.inner
    }

    fn get_mut(this: &mut ProtectedString) -> &mut String {
        &mut this.inner
    }
}

impl Drop for ProtectedString {
    fn drop(&mut self) {
        let len = ProtectedString::get_mut(self).len();
        unsafe {
            ptr_write_bytes_volatile(ProtectedString::get_mut(self).as_mut_str().as_bytes_mut().as_mut_ptr(), 0, len);
        }
    }
}

impl std::ops::Deref for ProtectedString {
    type Target = str;

    fn deref(&self) -> &str {
        &self.inner
    }
}

/// A vector of bytes that has its memory zeroed when it is dropped.
/// #TODO In KeePass's implementation the bytes are stored encrypted in memory.
///       I'm not sure how useful that is since it's constantly being unencrypted anyway
///       so I'll leave the implementation like this for now.
#[derive(Clone, PartialEq, Eq)]
pub struct ProtectedBinary {
    inner: Vec<u8>,
}

impl ProtectedBinary {
    pub fn empty() -> ProtectedBinary {
        Self::wrap(Vec::with_capacity(0))
    }

    pub fn new(len: usize) -> ProtectedBinary {
        let mut v = Vec::new();
        v.resize(len, 0);
        Self::wrap(v)
    }

    pub fn copy_slice(src: &[u8]) -> ProtectedBinary {
        let mut v = Vec::with_capacity(src.len());
        for b in src.iter() {
            v.push(*b);
        }
        Self::wrap(v)
    }

    pub fn wrap(value: Vec<u8>) -> ProtectedBinary {
        ProtectedBinary {
            inner: value
        }
    }

    pub fn get(this: &ProtectedBinary) -> &[u8] {
        &this.inner
    }

    fn get_mut(this: &mut ProtectedBinary) -> &mut Vec<u8> {
        &mut this.inner
    }

    /// Copies some data into a protected binary.
    pub fn copy_into(this: &mut ProtectedBinary, offset: usize, src: &[u8]) {
        assert!(offset < this.len(), "offset is out of bounds");

        let len = if src.len() < (this.len() - offset) {
            src.len()
        } else {
            this.len() - offset
        };

        for idx in 0..len {
            unsafe {
                *(Self::get_mut(this).get_unchecked_mut(idx + offset)) = *src.get_unchecked(idx);
            }
        }
    }
}

impl Drop for ProtectedBinary {
    fn drop(&mut self) {
        let len = ProtectedBinary::get_mut(self).len();
        unsafe {
            ptr_write_bytes_volatile(ProtectedBinary::get_mut(self).as_mut_ptr(), 0, len);
        }
    }
}

impl Default for ProtectedBinary {
    fn default() -> ProtectedBinary {
        ProtectedBinary {
            inner: Default::default(),
        }
    }
}

impl std::ops::Deref for ProtectedBinary {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        &self.inner
    }
}

impl std::convert::AsRef<[u8]> for ProtectedBinary {
    fn as_ref(&self) -> &[u8] {
        &self.inner
    }
}
