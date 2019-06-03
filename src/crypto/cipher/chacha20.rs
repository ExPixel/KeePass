use std::io::Read;
use crate::database::PwUUID;
use super::CipherEngine;
use super::CtrBlockCipher;

/// The basic operation of the ChaCha algorithm is the quarter round.  It
/// operates on four 32-bit unsigned integers, denoted a, b, c, and d.
/// The operation is as follows (in C-like notation):
///
/// 1.  a += b; d ^= a; d <<<= 16;
/// 2.  c += d; b ^= c; b <<<= 12;
/// 3.  a += b; d ^= a; d <<<= 8;
/// 4.  c += d; b ^= c; b <<<= 7;
///
/// Where "+" denotes integer addition modulo 2^32, "^" denotes a bitwise
/// Exclusive OR (XOR), and "<<< n" denotes an n-bit left rotation
/// (towards the high bits).
#[inline]
fn quarter_round(mut a: u32, mut b: u32, mut c: u32, mut d: u32) -> (u32, u32, u32, u32) {
    a = a.wrapping_add(b); d ^= a; d = d.rotate_left(16);
    c = c.wrapping_add(d); b ^= c; b = b.rotate_left(12);
    a = a.wrapping_add(b); d ^= a; d = d.rotate_left( 8);
    c = c.wrapping_add(d); b ^= c; b = b.rotate_left( 7);
    return (a, b, c, d);
}

/// Applies a quarter round to a 16 int(32 bits) chacha state.
#[inline]
fn state_quarter_round(state: &mut [u32], idx_a: usize, idx_b: usize, idx_c: usize, idx_d: usize) {
    let (a, b, c, d) = (state[idx_a], state[idx_b], state[idx_c], state[idx_d]);
    let (a, b, c, d) = quarter_round(a, b, c, d);
    state[idx_a] = a;
    state[idx_b] = b;
    state[idx_c] = c;
    state[idx_d] = d;
}

#[cfg(target_endian = "little")]
#[inline]
fn read32_le(bytes: &[u8], index: usize) -> u32 {
    assert!(index < bytes.len() + 4);

    unsafe {
        *(bytes.as_ptr().offset(index as isize) as *const u32)
    }
}

#[cfg(target_endian = "big")]
#[inline]
fn read32_le(bytes: &[u8], index: usize) -> u32 {
    assert!(index < bytes.len() + 4);

    let be = unsafe {
        *(bytes.as_ptr().offset(index as isize) as *const u32)
    };
    be.swap_bytes()
}

pub struct ChaCha20 {
    state:          [u32; 16],
}

impl ChaCha20 {
    #[cfg(test)]
    pub fn with_block_count(block_count: u32, key: &[u8], nonce: &[u8]) -> ChaCha20 {
        let mut chacha = ChaCha20::new(key, nonce);
        chacha.state[12] = 1;
        return chacha;
    }

    pub fn new(key: &[u8], nonce: &[u8]) -> ChaCha20 {
        assert!(key.len() == 32, "Key length must be 32 bytes.");
        assert!(nonce.len() == 12, "Nonce length must be 12 bytes.");

        ChaCha20 {
            state: [
                // ChaCha20 Constants
                0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,

                // Key
                read32_le(key,  0), read32_le(key,  4),
                read32_le(key,  8), read32_le(key, 12),
                read32_le(key, 16), read32_le(key, 20),
                read32_le(key, 24), read32_le(key, 28),

                // Block Counter
                0,

                // Nonce
                read32_le(nonce, 0),
                read32_le(nonce, 4),
                read32_le(nonce, 8),
            ],
        }
    }

    pub fn next_block(&mut self, dest: &mut [u8]) {
        assert!(dest.len() >= 64, "Dest must be at least 64 bytes in length.");

        let mut working_state = unsafe {
            std::slice::from_raw_parts_mut(dest.as_mut_ptr() as *mut u32, 16)
        };
        working_state.copy_from_slice(&self.state);

        // ChaCha20 runs 20 rounds, alternating between "column rounds" and
        // "diagonal rounds".  Each round consists of four quarter-rounds, and
        // they are run as follows.  Quarter rounds 1-4 are part of a "column"
        // round, while 5-8 are part of a "diagonal" round:
        //
        // 1.  QUARTERROUND ( 0, 4, 8,12)
        // 2.  QUARTERROUND ( 1, 5, 9,13)
        // 3.  QUARTERROUND ( 2, 6,10,14)
        // 4.  QUARTERROUND ( 3, 7,11,15)
        // 5.  QUARTERROUND ( 0, 5,10,15)
        // 6.  QUARTERROUND ( 1, 6,11,12)
        // 7.  QUARTERROUND ( 2, 7, 8,13)
        // 8.  QUARTERROUND ( 3, 4, 9,14)
        //
        // At the end of 20 rounds (or 10 iterations of the above list), we add
        // the original input words to the output words, and serialize the
        // result by sequencing the words one-by-one in little-endian order.
        //
        // Note: "addition" in the above paragraph is done modulo 2^32.  In some
        // machine languages, this is called carryless addition on a 32-bit
        // word.
        for _ in 0..10 {
            state_quarter_round(&mut working_state, 0, 4, 8,12);
            state_quarter_round(&mut working_state, 1, 5, 9,13);
            state_quarter_round(&mut working_state, 2, 6,10,14);
            state_quarter_round(&mut working_state, 3, 7,11,15);
            state_quarter_round(&mut working_state, 0, 5,10,15);
            state_quarter_round(&mut working_state, 1, 6,11,12);
            state_quarter_round(&mut working_state, 2, 7, 8,13);
            state_quarter_round(&mut working_state, 3, 4, 9,14);
        }

        for idx in 0..self.state.len() {
            working_state[idx] = self.state[idx].wrapping_add(working_state[idx]);
        }

        if let Some(res) = self.state[12].checked_add(1) {
            self.state[12] = res;
        } else {
            panic!("ChaCha20 block counter overflow.");
        }

        // If we're not already on a little-endian platform, we reverse the byte order
        // of the words in the working state:
        #[cfg(target_endian = "big")]
        {
            for word in working_state.iter_mut() {
                *word = (*word).swap_bytes();
            }
        }
    }
}

impl CtrBlockCipher for ChaCha20 {
    fn apply_keystream(&mut self, data: &mut [u8]) {
        let mut idx = 0;
        let mut block = [0u8; 64];

        while idx < data.len() {
            self.next_block(&mut block);
            crate::memutil::xor_slices(&mut data[idx..], &block); // This will automatically trim the slices.
            idx += block.len();
        }
    }
}

impl Drop for ChaCha20 {
    fn drop(&mut self) {
        crate::memutil::zero_slice(&mut self.state);
    }
}

pub struct ChaCha20Engine;

impl ChaCha20Engine {
    pub const UUID: PwUUID = PwUUID::wrap([
        0xD6, 0x03, 0x8A, 0x2B, 0x8B, 0x6F, 0x4C, 0xB5,
        0xA5, 0x24, 0x33, 0x9A, 0x31, 0xDB, 0xB5, 0x9A
    ]);

    pub const NAME: &'static str = "ChaCha20 (256, RFC 7539)";
}

impl CipherEngine for ChaCha20Engine {
    fn cipher_uuid(&self) -> PwUUID {
        ChaCha20Engine::UUID
    }

    fn display_name(&self) -> &'static str {
        ChaCha20Engine::NAME
    }

    fn encrypt_stream(&self, stream: Box<Read>, key: &[u8], iv: &[u8]) -> Box<Read> {
        Box::new(ChaCha20Encrypt::new(ChaCha20::new(key, iv), stream))
    }

    fn decrypt_stream(&self, stream: Box<Read>, key: &[u8], iv: &[u8]) -> Box<Read> {
        // decrypt is the same as encrypt
        Box::new(ChaCha20Encrypt::new(ChaCha20::new(key, iv), stream))
    }
}

/// This is used both for encryption and decryption.
struct ChaCha20Encrypt {
    /// ChaCha20 instance used for encryption.
    chacha: ChaCha20,

    /// Stream being read and encrypted on demand.
    stream: Box<Read>,

    /// Buffer containing data that has already been encrypted.
    /// This buffer is also used to temporarily hold unencrypted data while reading.
    buffer: [u8; 64],

    /// The current location in the buffer.
    cursor: usize,

    /// The amount of data currently available in the buffer.
    buflen: usize,
}

impl ChaCha20Encrypt {
    pub fn new(chacha: ChaCha20, stream: Box<Read>) -> ChaCha20Encrypt {
        ChaCha20Encrypt {
            chacha: chacha,
            stream: stream,
            buffer: [0u8; 64],
            cursor: 0,
            buflen: 0,
        }
    }
}

impl Read for ChaCha20Encrypt {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        // if all of the data in the buffer has already been read.
        if self.cursor >= self.buflen {
            self.cursor = 0;
            self.buflen = 0;

            // Attempt to fill the buffer before encrypting.
            while self.buflen < self.buffer.len() {
                match self.stream.read(&mut self.buffer[self.buflen..]) {
                    Ok(0) => {
                        break; // EOF
                    },
                    Ok(read) => {
                        self.buflen += read;
                    },
                    Err(ref err) if err.kind() == std::io::ErrorKind::Interrupted => {
                        continue; // Non-fatal error, retry.
                    },
                    Err(err) => {
                        return Err(err)
                    },
                }
            }

            if self.buflen == 0 {
                return Ok(0); // Nothing left to encrypt.
            }

            // Must make sure that we are always passing a buffer with a length of 64 bytes here
            // until the very end so that pieces of the ChaCha encryption blocks aren't thrown away.
            self.chacha.apply_keystream(&mut self.buffer[0..self.buflen]);
        }

        let minlen = std::cmp::min(buf.len(), self.buflen - self.cursor);
        (&mut buf[0..minlen]).copy_from_slice(&self.buffer[self.cursor..(self.cursor+minlen)]);
        self.cursor += minlen;

        Ok(minlen)
    }
}

impl Drop for ChaCha20Encrypt {
    fn drop(&mut self) {
        crate::memutil::zero_slice(&mut self.buffer);
    }
}


#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn chacha20_quarter_round_test() {
        let a = 0x11111111;
        let b = 0x01020304;
        let c = 0x9b8d6f43;
        let d = 0x01234567;

        let (a, b, c, d) = quarter_round(a, b, c, d);

        assert_eq!(a, 0xea2a92f4);
        assert_eq!(b, 0xcb1cf8ce);
        assert_eq!(c, 0x4581472e);
        assert_eq!(d, 0x5881c4bb);
    }

    #[test]
    fn chacha20_test() {
        let expected = [
            0x10, 0xf1, 0xe7, 0xe4, 0xd1, 0x3b, 0x59, 0x15, 0x50, 0x0f, 0xdd, 0x1f, 0xa3, 0x20, 0x71, 0xc4,
            0xc7, 0xd1, 0xf4, 0xc7, 0x33, 0xc0, 0x68, 0x03, 0x04, 0x22, 0xaa, 0x9a, 0xc3, 0xd4, 0x6c, 0x4e,
            0xd2, 0x82, 0x64, 0x46, 0x07, 0x9f, 0xaa, 0x09, 0x14, 0xc2, 0xd7, 0x05, 0xd9, 0x8b, 0x02, 0xa2,
            0xb5, 0x12, 0x9c, 0xd1, 0xde, 0x16, 0x4e, 0xb9, 0xcb, 0xd0, 0x83, 0xe8, 0xa2, 0x50, 0x3c, 0x4e,
        ];

        let test_key = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
            0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        ];

        let test_nonce = [
            0x00, 0x00, 0x00, 0x09, 0x00, 0x00,
            0x00, 0x4A, 0x00, 0x00, 0x00, 0x00,
        ];

        let mut chacha = ChaCha20::with_block_count(1, &test_key, &test_nonce);
        let mut buf = [0u8; 64];
        chacha.next_block(&mut buf);
        assert_eq!(&expected[0..], &buf[0..]);
    }

    #[test]
    fn chacha20_encryption_test() {
        let test_key = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
            0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        ];

        let test_nonce = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x4A, 0x00, 0x00, 0x00, 0x00,
        ];

        let test_plaintext = [
            0x4c, 0x61, 0x64, 0x69, 0x65, 0x73, 0x20, 0x61, 0x6e, 0x64, 0x20, 0x47, 0x65, 0x6e, 0x74, 0x6c,
            0x65, 0x6d, 0x65, 0x6e, 0x20, 0x6f, 0x66, 0x20, 0x74, 0x68, 0x65, 0x20, 0x63, 0x6c, 0x61, 0x73,
            0x73, 0x20, 0x6f, 0x66, 0x20, 0x27, 0x39, 0x39, 0x3a, 0x20, 0x49, 0x66, 0x20, 0x49, 0x20, 0x63,
            0x6f, 0x75, 0x6c, 0x64, 0x20, 0x6f, 0x66, 0x66, 0x65, 0x72, 0x20, 0x79, 0x6f, 0x75, 0x20, 0x6f,
            0x6e, 0x6c, 0x79, 0x20, 0x6f, 0x6e, 0x65, 0x20, 0x74, 0x69, 0x70, 0x20, 0x66, 0x6f, 0x72, 0x20,
            0x74, 0x68, 0x65, 0x20, 0x66, 0x75, 0x74, 0x75, 0x72, 0x65, 0x2c, 0x20, 0x73, 0x75, 0x6e, 0x73,
            0x63, 0x72, 0x65, 0x65, 0x6e, 0x20, 0x77, 0x6f, 0x75, 0x6c, 0x64, 0x20, 0x62, 0x65, 0x20, 0x69,
            0x74, 0x2e,
        ];

        let test_expected = [
            0x6e, 0x2e, 0x35, 0x9a, 0x25, 0x68, 0xf9, 0x80, 0x41, 0xba, 0x07, 0x28, 0xdd, 0x0d, 0x69, 0x81,
            0xe9, 0x7e, 0x7a, 0xec, 0x1d, 0x43, 0x60, 0xc2, 0x0a, 0x27, 0xaf, 0xcc, 0xfd, 0x9f, 0xae, 0x0b,
            0xf9, 0x1b, 0x65, 0xc5, 0x52, 0x47, 0x33, 0xab, 0x8f, 0x59, 0x3d, 0xab, 0xcd, 0x62, 0xb3, 0x57,
            0x16, 0x39, 0xd6, 0x24, 0xe6, 0x51, 0x52, 0xab, 0x8f, 0x53, 0x0c, 0x35, 0x9f, 0x08, 0x61, 0xd8,
            0x07, 0xca, 0x0d, 0xbf, 0x50, 0x0d, 0x6a, 0x61, 0x56, 0xa3, 0x8e, 0x08, 0x8a, 0x22, 0xb6, 0x5e,
            0x52, 0xbc, 0x51, 0x4d, 0x16, 0xcc, 0xf8, 0x06, 0x81, 0x8c, 0xe9, 0x1a, 0xb7, 0x79, 0x37, 0x36,
            0x5a, 0xf9, 0x0b, 0xbf, 0x74, 0xa3, 0x5b, 0xe6, 0xb4, 0x0b, 0x8e, 0xed, 0xf2, 0x78, 0x5e, 0x42,
            0x87, 0x4d,
        ];

        let mut chacha = ChaCha20::with_block_count(1, &test_key, &test_nonce);
        let mut test_result = test_plaintext.clone();
        chacha.apply_keystream(&mut test_result);
        assert_eq!(&test_expected[0..], &test_result[0..]);
    }

    #[test]
    fn chacha20_stream_encryption_test() {
        use std::io::Read as _;

        let test_key = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
            0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        ];

        let test_nonce = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x4A, 0x00, 0x00, 0x00, 0x00,
        ];

        static test_plaintext: [u8; 114] = [
            0x4c, 0x61, 0x64, 0x69, 0x65, 0x73, 0x20, 0x61, 0x6e, 0x64, 0x20, 0x47, 0x65, 0x6e, 0x74, 0x6c,
            0x65, 0x6d, 0x65, 0x6e, 0x20, 0x6f, 0x66, 0x20, 0x74, 0x68, 0x65, 0x20, 0x63, 0x6c, 0x61, 0x73,
            0x73, 0x20, 0x6f, 0x66, 0x20, 0x27, 0x39, 0x39, 0x3a, 0x20, 0x49, 0x66, 0x20, 0x49, 0x20, 0x63,
            0x6f, 0x75, 0x6c, 0x64, 0x20, 0x6f, 0x66, 0x66, 0x65, 0x72, 0x20, 0x79, 0x6f, 0x75, 0x20, 0x6f,
            0x6e, 0x6c, 0x79, 0x20, 0x6f, 0x6e, 0x65, 0x20, 0x74, 0x69, 0x70, 0x20, 0x66, 0x6f, 0x72, 0x20,
            0x74, 0x68, 0x65, 0x20, 0x66, 0x75, 0x74, 0x75, 0x72, 0x65, 0x2c, 0x20, 0x73, 0x75, 0x6e, 0x73,
            0x63, 0x72, 0x65, 0x65, 0x6e, 0x20, 0x77, 0x6f, 0x75, 0x6c, 0x64, 0x20, 0x62, 0x65, 0x20, 0x69,
            0x74, 0x2e,
        ];

        let test_expected = [
            0x6e, 0x2e, 0x35, 0x9a, 0x25, 0x68, 0xf9, 0x80, 0x41, 0xba, 0x07, 0x28, 0xdd, 0x0d, 0x69, 0x81,
            0xe9, 0x7e, 0x7a, 0xec, 0x1d, 0x43, 0x60, 0xc2, 0x0a, 0x27, 0xaf, 0xcc, 0xfd, 0x9f, 0xae, 0x0b,
            0xf9, 0x1b, 0x65, 0xc5, 0x52, 0x47, 0x33, 0xab, 0x8f, 0x59, 0x3d, 0xab, 0xcd, 0x62, 0xb3, 0x57,
            0x16, 0x39, 0xd6, 0x24, 0xe6, 0x51, 0x52, 0xab, 0x8f, 0x53, 0x0c, 0x35, 0x9f, 0x08, 0x61, 0xd8,
            0x07, 0xca, 0x0d, 0xbf, 0x50, 0x0d, 0x6a, 0x61, 0x56, 0xa3, 0x8e, 0x08, 0x8a, 0x22, 0xb6, 0x5e,
            0x52, 0xbc, 0x51, 0x4d, 0x16, 0xcc, 0xf8, 0x06, 0x81, 0x8c, 0xe9, 0x1a, 0xb7, 0x79, 0x37, 0x36,
            0x5a, 0xf9, 0x0b, 0xbf, 0x74, 0xa3, 0x5b, 0xe6, 0xb4, 0x0b, 0x8e, 0xed, 0xf2, 0x78, 0x5e, 0x42,
            0x87, 0x4d,
        ];

        let mut stream = Box::new(std::io::Cursor::new(&test_plaintext[0..]));
        let mut chacha = ChaCha20::with_block_count(1, &test_key, &test_nonce);
        let mut stream_encrypt = ChaCha20Encrypt::new(chacha, stream);
        let mut test_result = Vec::new();
        stream_encrypt.read_to_end(&mut test_result);
        assert_eq!(&test_expected[0..], &test_result[0..]);
    }
}

