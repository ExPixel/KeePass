pub mod chacha20;
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

pub trait CtrBlockCipher {
    /// XOR a keystream with the data.
    fn apply_keystream(&mut self, data: &mut [u8]);
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
