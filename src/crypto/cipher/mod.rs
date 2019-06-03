pub mod chacha20;
pub mod aes;

use std::io::Read;
use crate::database::PwUUID;
use self::chacha20::ChaCha20Engine;
use self::aes::StandardAesEngine;

pub fn get_cipher_engine(uuid: PwUUID) -> Option<Box<CipherEngine>> {
    match uuid {
        ChaCha20Engine::UUID => Some(Box::new(ChaCha20Engine{})),
        StandardAesEngine::UUID => Some(Box::new(StandardAesEngine{})),
        _ => None,
    }
}

pub trait CipherEngine {
    /// UUID of the engine.
    fn cipher_uuid(&self) -> PwUUID;

    /// Name displayed in the list of available encryption/decryption engines in the GUI.
    fn display_name(&self) -> &'static str;

    fn encrypt_stream(&self, stream: Box<Read>, key: &[u8], iv: &[u8]) -> Box<Read>;
    fn decrypt_stream(&self, stream: Box<Read>, key: &[u8], iv: &[u8]) -> Box<Read>;
}

pub trait CtrBlockCipher {
    /// XOR a keystream with the data.
    fn apply_keystream(&mut self, data: &mut [u8]);
}

