use super::Transform;
use std::io::Read;
use crate::database::PwUUID;
use super::CipherEngine;
use super::CtrBlockCipher;
use aes::Aes256;
use block_modes::block_padding::Pkcs7;
use block_modes::block_padding::Padding as _;
use aes::block_cipher_trait::generic_array::GenericArray;
use aes::block_cipher_trait::BlockCipher;
use crate::memutil;


pub const AES_KEY_SIZE: usize = 32;
pub const AES_BLOCK_SIZE: usize = 16;

pub struct StandardAesEngine;

impl StandardAesEngine {
    pub const UUID: PwUUID = PwUUID::wrap([
        0x31, 0xC1, 0xF2, 0xE6, 0xBF, 0x71, 0x43, 0x50,
        0xBE, 0x58, 0x05, 0x21, 0x6A, 0xFC, 0x5A, 0xFF,
    ]);

    pub const NAME: &'static str = "AES/Rijndael (256, FIPS 197)";
}

impl CipherEngine for StandardAesEngine {
    fn cipher_uuid(&self) -> PwUUID {
        StandardAesEngine::UUID
    }

    fn display_name(&self) -> &'static str {
        StandardAesEngine::NAME
    }

    fn key_length(&self) -> usize {
        32
    }

    fn iv_length(&self) -> usize {
        16
    }

    fn encrypt_stream(&self, key: &[u8], iv: &[u8]) -> Box<Transform> {
        Box::new(StandardAesEncrypt::new(key, iv))
    }

    fn decrypt_stream(&self, key: &[u8], iv: &[u8]) -> Box<Transform> {
        Box::new(StandardAesDecrypt::new(key, iv))
    }
}

/// AES256 CBC implementation.
struct StandardAesEncrypt {
    aes: Aes256,
    key: [u8; AES_KEY_SIZE],
    /// If the buffer has already been fully read, this contains the IV for the next block.
    /// If this has not been fully read, it contains whatever data is in the queue for reading.
    /// The buffer has double size of the block size to make space for padding.
    buffer: [u8; AES_BLOCK_SIZE * 2],
    cursor: usize,
    buflen: usize,
    done: bool,
}

impl StandardAesEncrypt {
    pub fn new(key: &[u8], iv: &[u8]) -> StandardAesEncrypt {
        assert!(key.len() == AES_KEY_SIZE, "bad key length");
        assert!( iv.len() == AES_BLOCK_SIZE, "bad IV length");

        let mut sae = StandardAesEncrypt {
            aes: Aes256::new_varkey(&key).unwrap(),
            key: [0u8; AES_KEY_SIZE],
            buffer: [0u8; AES_BLOCK_SIZE * 2],
            cursor: 0,
            buflen: 0,
            done: false,
        };

        (&mut sae.buffer[0..AES_BLOCK_SIZE]).copy_from_slice(iv);

        return sae;
    }
}

impl Transform for StandardAesEncrypt {
    fn transform(&mut self, stream: &mut Read, buf: &mut [u8]) -> std::io::Result<usize> {
        // if all of the data in the buffer has already been read.
        if self.cursor >= self.buflen {
            if self.done {
                return Ok(0);
            }

            self.cursor = 0;
            self.buflen = 0;

            let mut iv = [0u8; AES_BLOCK_SIZE];
            iv.copy_from_slice(&self.buffer[0..AES_BLOCK_SIZE]);

            // Attempt to fill the buffer before encrypting.
            while self.buflen < AES_BLOCK_SIZE {
                match stream.read(&mut self.buffer[self.buflen..AES_BLOCK_SIZE]) {
                    Ok(0) => {
                        self.done = true;
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

            if self.done {
                if self.buflen < AES_BLOCK_SIZE {
                    Pkcs7::pad_block(&mut self.buffer[0..AES_BLOCK_SIZE], self.buflen);

                    memutil::xor_slices(&mut self.buffer[0..AES_BLOCK_SIZE], &iv);

                    let mut gbuf = GenericArray::from_mut_slice(&mut self.buffer[0..AES_BLOCK_SIZE]);
                    self.aes.encrypt_block(&mut gbuf);
                    self.buflen = AES_BLOCK_SIZE;
                } else {
                    Pkcs7::pad_block(&mut self.buffer[AES_BLOCK_SIZE..], 0);

                    memutil::xor_slices(&mut self.buffer[0..AES_BLOCK_SIZE], &iv);

                    let mut gbuf = GenericArray::from_mut_slice(&mut self.buffer[0..AES_BLOCK_SIZE]);
                    self.aes.encrypt_block(&mut gbuf);

                    {
                        let (left, right) = self.buffer.split_at_mut(AES_BLOCK_SIZE);
                        memutil::xor_slices(right, left);
                    }

                    // encrypt the padding
                    let mut gbuf = GenericArray::from_mut_slice(&mut self.buffer[AES_BLOCK_SIZE..]);
                    self.aes.encrypt_block(&mut gbuf);

                    self.buflen = AES_BLOCK_SIZE * 2;
                }
            } else {
                memutil::xor_slices(&mut self.buffer[0..16], &iv);
                let mut gbuf = GenericArray::from_mut_slice(&mut self.buffer[0..AES_BLOCK_SIZE]);
                self.aes.encrypt_block(&mut gbuf);
                self.buflen = AES_BLOCK_SIZE;
            }
        }

        let minlen = std::cmp::min(buf.len(), self.buflen - self.cursor);
        (&mut buf[0..minlen]).copy_from_slice(&self.buffer[self.cursor..(self.cursor+minlen)]);
        self.cursor += minlen;

        Ok(minlen)
    }
}

/// AES256 CBC implementation.
struct StandardAesDecrypt {
    aes: Aes256,
    buffer: [u8; AES_BLOCK_SIZE],
    iv: [u8; AES_BLOCK_SIZE],
    cursor: usize,
    buflen: usize,
    next_byte: Option<u8>,
    done: bool,
}

impl StandardAesDecrypt {
    pub fn new(key: &[u8], iv: &[u8]) -> StandardAesDecrypt {
        assert!(key.len() == AES_KEY_SIZE, "bad key length");
        assert!( iv.len() == AES_BLOCK_SIZE, "bad IV length");

        let mut sad = StandardAesDecrypt {
            aes: Aes256::new_varkey(&key).unwrap(),
            buffer: [0u8; AES_BLOCK_SIZE],
            iv: [0u8; AES_BLOCK_SIZE],
            cursor: 0,
            buflen: 0,
            next_byte: None,
            done: false,
        };

        sad.iv.copy_from_slice(iv);

        return sad;
    }
}

impl Transform for StandardAesDecrypt {
    fn transform(&mut self, stream: &mut Read, buf: &mut [u8]) -> std::io::Result<usize> {
        // if all of the data in the buffer has already been read.
        if self.cursor >= self.buflen {
            if self.done {
                return Ok(0);
            }

            self.cursor = 0;
            self.buflen = 0;


            if let Some(b) = self.next_byte.take() {
                self.buffer[0] = b;
                self.buflen = 1;
            }

            let mut last_block = false;

            // Attempt to fill the buffer before encrypting.
            while self.buflen < AES_BLOCK_SIZE {
                match stream.read(&mut self.buffer[self.buflen..]) {
                    Ok(0) => {
                        last_block = true;
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

            // Check if this is the end of the stream byte reading one byte.
            if !last_block {
                let mut next_byte_arr = [0u8; 1];
                loop {
                    match stream.read(&mut next_byte_arr) {
                        Ok(0) => {
                            last_block = true;
                            break;
                        },
                        Ok(_) => {
                            self.next_byte = Some(next_byte_arr[0]);
                            break;
                        },
                        Err(ref err) if err.kind() == std::io::ErrorKind::Interrupted => {
                            continue; // Non-fatal error, retry.
                        },
                        Err(err) => {
                            return Err(err)
                        },
                    }
                }
            }

            assert!(self.buflen == AES_BLOCK_SIZE, "Corrupted AES256 cipher text.");

            let mut iv = [0u8; AES_BLOCK_SIZE];
            iv.copy_from_slice(&self.iv);
            self.iv.copy_from_slice(&self.buffer);

            if last_block {
                self.done = true;
                {
                    let mut gbuf = GenericArray::from_mut_slice(&mut self.buffer);
                    self.aes.decrypt_block(&mut gbuf);
                }
                memutil::xor_slices(&mut self.buffer, &iv);

                // @TODO replace this panic with an IO error.
                self.buflen = Pkcs7::unpad(&self.buffer).expect("Failed to unpad plaintext.").len();
            } else {
                {
                    let mut gbuf = GenericArray::from_mut_slice(&mut self.buffer);
                    self.aes.decrypt_block(&mut gbuf);
                }
                memutil::xor_slices(&mut self.buffer, &iv);
                self.buflen = AES_BLOCK_SIZE;
            }
        }

        let minlen = std::cmp::min(buf.len(), self.buflen - self.cursor);
        (&mut buf[0..minlen]).copy_from_slice(&self.buffer[self.cursor..(self.cursor+minlen)]);
        self.cursor += minlen;

        Ok(minlen)
    }
}

#[cfg(test)]
pub mod test {
    use super::super::TransformRead;
    use super::*;
    use crate::memutil;

    #[test]
    pub fn aes_test_cbc_single_block() {
        use std::io::Read as _;

        let key = memutil::hex_to_bytes(b"603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4");
        let iv = memutil::hex_to_bytes(b"39F23369A9D9BACFA530E26304231461");
        let plaintext = memutil::hex_to_bytes(b"f69f2445df4f9b17ad2b417be66c3710");
        let ciphertext = memutil::hex_to_bytes(b"b2eb05e2c39be9fcda6c19078c6a9d1b");
        let ciphertext_padded = memutil::hex_to_bytes(b"B2EB05E2C39BE9FCDA6C19078C6A9D1B3F461796D6B0D6B2E0C2A72B4D80E644");

        let mut read_stream = std::io::Cursor::new(plaintext.clone());
        let mut encrypt_transform = StandardAesEncrypt::new(&key, &iv);
        let mut encrypt_stream = TransformRead::new(&mut read_stream, &mut encrypt_transform);
        let mut encrypt_result = Vec::new();
        encrypt_stream.read_to_end(&mut encrypt_result);
        assert_eq!(&ciphertext_padded[0..], &encrypt_result[0..]);

        let mut read_stream = std::io::Cursor::new(ciphertext_padded.clone());
        let mut decrypt_transform = StandardAesDecrypt::new(&key, &iv);
        let mut decrypt_stream = TransformRead::new(&mut read_stream, &mut decrypt_transform);
        let mut decrypt_result = Vec::new();
        decrypt_stream.read_to_end(&mut decrypt_result);
        assert_eq!(&plaintext[0..], &decrypt_result[0..]);
    }

    #[test]
    pub fn aes_test_cbc_multi_block() {
        // AES RFC doesn't have test vectors for this one so I just check that the data is
        // decrypted correctly.

        let key = memutil::hex_to_bytes(b"603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4");
        let iv = memutil::hex_to_bytes(b"39F23369A9D9BACFA530E26304231461");

        // 44 bytes (more than one block and not divisible by 16)
        let plaintext = memutil::hex_to_bytes(b"f69f2445df4f9b17ad2b417be66c37109da71b2378a854f670ed165bac3dbc4814f4da5f00a08772b63c6a04");

        let mut read_stream = std::io::Cursor::new(plaintext.clone());
        let mut encrypt_transform = StandardAesEncrypt::new(&key, &iv);
        let mut encrypt_stream = TransformRead::new(&mut read_stream, &mut encrypt_transform);
        let mut encrypt_result = Vec::new();
        encrypt_stream.read_to_end(&mut encrypt_result);

        let mut read_stream = std::io::Cursor::new(encrypt_result);
        let mut decrypt_transform = StandardAesDecrypt::new(&key, &iv);
        let mut decrypt_stream = TransformRead::new(&mut read_stream, &mut decrypt_transform);
        let mut decrypt_result = Vec::new();
        decrypt_stream.read_to_end(&mut decrypt_result);
        assert_eq!(&plaintext[0..], &decrypt_result[0..]);
    }
}
