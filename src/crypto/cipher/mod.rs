pub mod chacha20;
pub mod salsa20;
pub mod aes;

use std::io::Read;
use crate::database::PwUUID;
use self::chacha20::ChaCha20Engine;
use self::aes::StandardAesEngine;

static ENGINE_CHACHA20: ChaCha20Engine = ChaCha20Engine{};
static ENGINE_STANDARD_AES: StandardAesEngine = StandardAesEngine{};

pub fn get_cipher_engine(uuid: &PwUUID) -> Option<&'static CipherEngine> {
    match *uuid {
        ChaCha20Engine::UUID => Some(&ENGINE_CHACHA20),
        StandardAesEngine::UUID => Some(&ENGINE_STANDARD_AES),
        _ => None,
    }
}

pub trait CipherEngine {
    /// UUID of the engine.
    fn cipher_uuid(&self) -> PwUUID;

    /// Name displayed in the list of available encryption/decryption engines in the GUI.
    fn display_name(&self) -> &'static str;

    /// Length of encryption key in bytes. Base CipherEngine assumes 32.
    fn key_length(&self) -> usize { 32 }

    /// Length of the initialization vector in bytes. Base CipherEngine assumes 16.
    fn iv_length(&self) -> usize { 16 }


    fn encrypt_stream(&self, key: &[u8], iv: &[u8]) -> Box<Transform>;
    fn decrypt_stream(&self, key: &[u8], iv: &[u8]) -> Box<Transform>;
}

pub trait BlockCipher {
    fn next_block(&mut self, data: &mut [u8]);
}

pub struct CtrBlockCipher64<C: BlockCipher> {
    block: [u8; 64],
    cipher: C,

    /// current position in the block
    cursor: usize,
}

impl<C: BlockCipher> CtrBlockCipher64<C> {
    pub fn new(cipher: C) -> CtrBlockCipher64<C> {
        CtrBlockCipher64 {
            block: [0u8; 64],
            cipher: cipher,
            cursor: 64, // start at the end
        }
    }

    /// XOR a keystream with the data.
    fn apply_keystream_64(&mut self, data: &mut [u8]) {
        let mut offset = 0;

        while offset < data.len() {
            if self.cursor >= self.block.len() {
                self.cipher.next_block(&mut self.block);
                self.cursor = 0;
            }
            let c = std::cmp::min(data.len() - offset, self.block.len() - self.cursor);
            crate::memutil::xor_slices(&mut data[offset..(offset + c)], &self.block[self.cursor..(self.cursor + c)]);
            self.cursor += c;
            offset += c;
        }
    }
}

impl<C: BlockCipher> Drop for CtrBlockCipher64<C> {
    fn drop(&mut self) {
        crate::memutil::zero_slice(&mut self.block);
    }
}

pub trait CtrBlockCipher {
    /// XOR a keystream with the data.
    fn apply_keystream(&mut self, data: &mut [u8]);
}

impl<C: BlockCipher> CtrBlockCipher for CtrBlockCipher64<C> {
    #[inline(always)]
    fn apply_keystream(&mut self, data: &mut [u8]) {
        self.apply_keystream_64(data)
    }
}

impl<T> Transform for T where T: CtrBlockCipher {
    fn transform(&mut self, src: &mut Read, buf: &mut [u8]) -> std::io::Result<usize> {
        let mut buflen = 0;
        while buflen < buf.len() {
            match src.read(&mut buf[buflen..]) {
                Ok(0) => {
                    break;
                },
                Ok(read) => {
                    buflen += read;
                },
                Err(ref err) if err.kind() == std::io::ErrorKind::Interrupted => {
                    continue; // Non-fatal error, retry.
                },
                Err(err) => {
                    return Err(err)
                },
            }
        }

        self.apply_keystream(&mut buf[0..buflen]);

        Ok(buflen)
    }
}

pub trait Transform {
    /// Attempt to fill `buf` by reading and transforming data from `src`.
    fn transform(&mut self, src: &mut Read, buf: &mut [u8]) -> std::io::Result<usize>;
}

pub struct TransformRead<'r, 't> {
    src: &'r mut Read,
    transform: &'t mut Transform,
}

impl<'r, 't> TransformRead<'r, 't> {
    pub fn new(src: &'r mut Read, transform: &'t mut Transform) -> TransformRead<'r, 't> {
        TransformRead {
            src: src,
            transform: transform,
        }
    }

    pub fn with<F>(src: &'r mut Read, transform: &'t mut Transform, f: F) -> std::io::Result<()> where F: FnOnce(TransformRead<'r, 't>) -> std::io::Result<()> {
        f(TransformRead::new(src, transform))
    }
}

impl<'r, 't> Read for TransformRead<'r, 't> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.transform.transform(self.src, buf)
    }
}
