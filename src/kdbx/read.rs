use std::io::prelude::*;
use std::io::BufReader;
use std::path::Path;
use xml::reader::{EventReader, XmlEvent};
use sha2::{Sha256, Sha512, Digest as _};

use crate::error::{self, Error};
use crate::database::{PwDatabase, PwUUID, PwCompressionAlgorithm};
use crate::memutil::{self, ProtectedBinary};
use crate::ioutil::{self, StoredReadRef};
use crate::crypto::kdf;
use crate::crypto::crs::CrsAlgorithm;
use crate::crypto::cipher::{CipherEngine, TransformRead};
use crate::cryptoutil;

use super::*;

pub struct Kdbx {
    signature: (u32, u32),
    version: u32,
    master_seed: ProtectedBinary,
    encryption_iv: ProtectedBinary,
    inner_random_stream_key: ProtectedBinary,
    stream_start_bytes: ProtectedBinary,
    inner_random_stream_algorithm: CrsAlgorithm,
    hash_of_header: ProtectedBinary,
    hash_of_file_on_disk: ProtectedBinary,
}

impl Kdbx {
    pub fn new() -> Kdbx {
        Kdbx {
            signature: (0, 0),
            version: 0,
            master_seed: ProtectedBinary::empty(),
            encryption_iv: ProtectedBinary::empty(),
            inner_random_stream_key: ProtectedBinary::empty(),
            stream_start_bytes: ProtectedBinary::empty(),
            inner_random_stream_algorithm: CrsAlgorithm::None,
            hash_of_header: ProtectedBinary::empty(),
            hash_of_file_on_disk: ProtectedBinary::empty(),
        }
    }

    pub fn get_cipher(database: &PwDatabase, enc_key_len: &mut usize, enc_iv_len: &mut usize) -> Option<&'static CipherEngine> {
        use crate::crypto::cipher;
        let maybe_engine = cipher::get_cipher_engine(&database.data_cipher_uuid);
        if let Some(ref engine) = maybe_engine {
            *enc_key_len = engine.key_length();
            *enc_iv_len = engine.iv_length();
        } else {
            *enc_key_len = 32;
            *enc_iv_len = 16;
        };
        return maybe_engine;
    }

    pub fn compute_keys(&self, database: &PwDatabase, cipherkey: &mut [u8], hmackey64: &mut [u8]) -> Result<(), Error> {
        debug_assert!(self.master_seed.len() == 32, "Master seed must have a length of 32 bytes.");
        assert!(hmackey64.len() == 64, " HMac64 length must be 64 bytes.");
        let mut cmp = [0u8; 65];
        (&mut cmp[0..32]).copy_from_slice(&self.master_seed);

        let binuser = database.master_key.generate_key_32(&database.kdf_parameters)?;
        (&mut cmp[32..64]).copy_from_slice(&binuser);
        cryptoutil::resize_key(&cmp[0..64], cipherkey);
        cmp[64] = 1;

        let mut hasher = Sha512::new();
        hasher.input(&cmp[0..]);
        hmackey64.copy_from_slice(&hasher.result());

        memutil::zero_slice(&mut cmp);

        Ok(())
    }
}


pub fn load_kdbx_file<PathRef: AsRef<Path>>(p: PathRef, database: &mut PwDatabase) -> Result<(), Error> {
    let file = std::fs::File::open(p).map_err(|e| Error::IO(e))?;
    let mut buffered = BufReader::new(file);
    load_kdbx(&mut buffered, database)
}

pub fn load_kdbx<R: Read>(input: &mut R, database: &mut PwDatabase) -> Result<(), Error> {
    let mut kdbx = Kdbx::new();

    let mut input = ioutil::ReadInto::new(input, Sha256::new());

    let header_data = {
        let mut stored_input = ioutil::StoredReadRef::new(&mut input);
        load_header(&mut stored_input, database, &mut kdbx)?;
        stored_input.data()
    };

    kdbx.hash_of_header = {
        let mut hasher = Sha256::new();
        hasher.input(&header_data);
        ProtectedBinary::copy_slice(&hasher.result())
    };

    let mut enc_key_len = 0;
    let mut enc_iv_len = 0;
    let cipher_engine = Kdbx::get_cipher(database, &mut enc_key_len, &mut enc_iv_len).ok_or(Error::BadFormat("Bad cipher engine UUID."))?;

    let mut cipher_key_and_iv = Vec::with_capacity(enc_key_len + enc_iv_len);
    cipher_key_and_iv.resize(enc_key_len + enc_iv_len, 0);
    let mut hmackey64 = [0u8; 64];
    kdbx.compute_keys(database, &mut cipher_key_and_iv[0..enc_key_len], &mut hmackey64)?;

    (&mut cipher_key_and_iv[enc_key_len..]).copy_from_slice(&kdbx.encryption_iv[0..enc_iv_len]);
    let cipherkey = &cipher_key_and_iv[0..enc_key_len];
    let cipheriv = &cipher_key_and_iv[enc_key_len..];

    if kdbx.version < FILE_VERSION_32_4 {
        // KDBX < 4

        let mut decrypt_transform = cipher_engine.decrypt_stream(cipherkey, cipheriv);
        let mut decrypt_stream = TransformRead::new(&mut input, &mut *decrypt_transform);

        let mut start_stream_bytes = [0u8; 32];
        decrypt_stream.read_exact(&mut start_stream_bytes[0..]).map_err(|e| Error::IO(e))?;
        if start_stream_bytes != &kdbx.stream_start_bytes[0..] {
            return Err(Error::BadFormat("File corrupted (bad start bytes)"));
        }

        load_kdbx_unencrypted(&mut decrypt_stream, database, &kdbx)?;
    } else {
        // KDBX >= 4
        unimplemented!("kdbx.version >= 4 decryption no yet implemented");
    }


    Ok(())
}

pub fn load_kdbx_unencrypted<R: Read>(input: &mut R, database: &mut PwDatabase, kdbx: &Kdbx) -> Result<(), Error> {
    let parser = EventReader::new(input);

    for evt in parser {
        match evt {
            Ok(XmlEvent::StartElement { name, .. }) => {
                println!("start-element: {}", name);
            }

            Ok(XmlEvent::EndElement { name }) => {
                println!("end-element: {}", name);
            }

            _ => {}
        }
    }

    Ok(())
}

fn load_inner_header<R: Read>(input: &mut R, database: &mut PwDatabase, kdbx: &mut Kdbx) -> Result<(), Error> {
    Ok(())
}


fn load_header<R: Read>(input: &mut R, database: &mut PwDatabase, kdbx: &mut Kdbx) -> Result<(), Error> {
    let sig1 = ioutil::io_read_u32(input)?;
    let sig2 = ioutil::io_read_u32(input)?;
    let signature = (sig1, sig2);

    if signature == FILE_SIGNATURE_OLD {
        return Err(Error::OldFormat(error::KEEPASS_VERSION_1x));
    }

    if signature != FILE_SIGNATURE && signature != FILE_SIGNATURE_PRE_RELEASE {
        return Err(Error::InvalidSignature(signature));
    }
    kdbx.signature = signature;

    let version = ioutil::io_read_u32(input)?;
    if (version & FILE_VERSION_CRITICAL_MASK) > (FILE_VERSION_32 & FILE_VERSION_CRITICAL_MASK) {
        return Err(Error::UnsupportedFileVersion(version));
    }
    kdbx.version = version;

    let mut buffer: Vec<u8> = Vec::with_capacity(16);

    loop {
        if !read_header_field(input, database, kdbx, &mut buffer)? {
            break
        }
    }

    Ok(())
}


fn read_header_field<R: Read>(input: &mut R, database: &mut PwDatabase, kdbx: &mut Kdbx, buffer: &mut Vec<u8>) -> Result<bool, Error> {
    let field_id = ioutil::io_read_u8(input)?;
    let size: i32;

    if kdbx.version < FILE_VERSION_32_4 {
        size = ioutil::io_read_i16(input)? as i32;
    } else {
        size = ioutil::io_read_i32(input)?;
    }

    if size < 0 {
        return Err(Error::BadFormat("File Corrupted"));
    } else if size > 0 {
        buffer.resize(size as usize, 0);
        input.read_exact(&mut buffer[0..(size as usize)]).map_err(|e| Error::IO(e))?;
    }

    let data = &buffer[0..(size as usize)];

    let mut result = true;
    match KdbxHeaderFieldID::from_bits(field_id) {
        Some(KdbxHeaderFieldID::EndOfHeader) => {
            result = false; // returning false indicates the end of the header
        },

        Some(KdbxHeaderFieldID::CipherID) => {
            if data.len() != crate::database::UUID_SIZE {
                return Err(Error::BadFormat("Invalid Cipher"));
            } else {
                database.data_cipher_uuid = PwUUID::from_slice(data);
                debug_println!("Set database cipher UUID.");
            }
        },

        Some(KdbxHeaderFieldID::CompressionFlags) => {
            if data.len() < 4 {
                return Err(Error::BadFormat("Invalid Compression Algorithm"));
            } else {
                let compression_algorithm_id = memutil::bytes_to_u32(data);
                if let Some(compression_algorithm) = PwCompressionAlgorithm::from_int(compression_algorithm_id) {
                    debug_println!("Set database compression algorithm.");
                    database.compression_algorithm = compression_algorithm;
                } else {
                    return Err(Error::BadFormat("Invalid compression algorithm."));
                }
            }
        },

        Some(KdbxHeaderFieldID::MasterSeed) => {
            kdbx.master_seed = ProtectedBinary::copy_slice(data);
            database.context.crypto_random.add_entropy(data);
            debug_println!("Set MasterSeed.");
        },

        // Obsolete; for backwards compatibility only
        Some(KdbxHeaderFieldID::TransformSeed) => {
            debug_assert!(kdbx.version < FILE_VERSION_32_4, "New KDBX file is using parameter `TransformSeed` from legacy KDBX versions.");
            let kdf = kdf::KdfEngine::Aes;
            if database.kdf_parameters.kdf_uuid != kdf.uuid() {
                database.kdf_parameters = kdf.default_parameters();
            }
            database.kdf_parameters.dict.set_arr(kdf::aes::PARAM_SEED, data);
            debug_println!("Set TransformSeed.");
        },

        // Obsolete; for backwards compatibility only
        Some(KdbxHeaderFieldID::TransformRounds) => {
            debug_assert!(kdbx.version < FILE_VERSION_32_4, "New KDBX file is using parameter `TransformRounds` from legacy KDBX versions.");
            let kdf = kdf::KdfEngine::Aes;
            if database.kdf_parameters.kdf_uuid != kdf.uuid() {
                database.kdf_parameters = kdf.default_parameters();
            }
            database.kdf_parameters.dict.set_u64(kdf::aes::PARAM_ROUNDS, memutil::bytes_to_u64(data));
            debug_println!("Set TransformRounds.");
        },

        Some(KdbxHeaderFieldID::EncryptionIV) => {
            debug_assert!(kdbx.version < FILE_VERSION_32_4, "New KDBX file is using parameter `EncryptionIV` from legacy KDBX versions.");
            kdbx.encryption_iv = ProtectedBinary::copy_slice(data);
            debug_println!("Set EncryptionIV.");
        },

        Some(KdbxHeaderFieldID::InnerRandomStreamKey) => {
            debug_assert!(kdbx.version < FILE_VERSION_32_4, "New KDBX file is using parameter `InnerRandomStreamKey` from legacy KDBX versions.");
            kdbx.inner_random_stream_key = ProtectedBinary::copy_slice(data);
            debug_println!("Set InnerRandomStreamKey.");
        },

        Some(KdbxHeaderFieldID::StreamStartBytes) => {
            debug_assert!(kdbx.version < FILE_VERSION_32_4, "New KDBX file is using parameter `StreamStartBytes` from legacy KDBX versions.");
            kdbx.stream_start_bytes = ProtectedBinary::copy_slice(data);
            debug_println!("Set StreamStartBytes.");
        },

        Some(KdbxHeaderFieldID::InnerRandomStreamID) => {
            let stream_id = memutil::bytes_to_u32(data);
            if let Some(alg) = CrsAlgorithm::from_int(stream_id) {
                kdbx.inner_random_stream_algorithm = alg;
            } else {
                return Err(Error::BadFormat("Unknown stream cipher algorithm."));
            }
            debug_println!("Set InnerRandomStreamID");
        },

        Some(KdbxHeaderFieldID::KdfParameters) => {
            database.kdf_parameters.clear();
            kdf::KdfParameters::deserialize(&mut database.kdf_parameters, data);
            debug_println!("Set KdfParameters");
        },

        Some(KdbxHeaderFieldID::PublicCustomData) => {
            debug_assert!(database.public_custom_data.len() == 0, "Public custom data was not empty.");
            database.public_custom_data.clear();
            crate::vdict::VariantDict::deserialize(&mut database.public_custom_data, data);
            debug_println!("Set PublicCustom Data");
        },

        Some(_) => {
            debug_println!("Unhandled Known Header ID: {:b}", field_id);
        },

        _ => {
            debug_println!("Unknown Header ID: {:b}", field_id);
        },
    }

    Ok(result)
}
