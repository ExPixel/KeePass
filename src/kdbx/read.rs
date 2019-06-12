use std::io::prelude::*;
use chrono::prelude::*;
use std::io::BufReader;
use std::path::Path;
use sha2::{Sha256, Sha512, Digest as _};
use flate2::read::GzDecoder;
use xml::reader::{EventReader, XmlEvent};

use crate::error::{self, Error};
use crate::database::{PwDatabase, PwUUID, PwCompressionAlgorithm};
use crate::memutil;
use crate::security::{ProtectedBinary, XorredBuffer};
use crate::ioutil::{self, StoredReadRef};
use crate::crypto::kdf;
use crate::crypto::crypto_random_stream::{CrsAlgorithm, CryptoRandomStream};
use crate::crypto::cipher::{CipherEngine, TransformRead};
use crate::crypto::hashed_block_stream::HashedBlockRead;
use crate::cryptoutil;

use super::*;

pub struct Kdbx {
    format: KdbxFormat,
    signature: (u32, u32),
    version: u32,
    master_seed: ProtectedBinary,
    encryption_iv: ProtectedBinary,
    inner_random_stream_key: ProtectedBinary,
    stream_start_bytes: ProtectedBinary,
    random_stream: CryptoRandomStream,
    inner_random_stream_algorithm: CrsAlgorithm,
    hash_of_header: ProtectedBinary,
    hash_of_file_on_disk: ProtectedBinary,
    binaries: Vec<ProtectedBinary>,

    repair_mode: bool,
}

impl Kdbx {
    pub fn new() -> Kdbx {
        Kdbx {
            format: KdbxFormat::Default,
            signature: (0, 0),
            version: 0,
            master_seed: ProtectedBinary::empty(),
            encryption_iv: ProtectedBinary::empty(),
            inner_random_stream_key: ProtectedBinary::empty(),
            stream_start_bytes: ProtectedBinary::empty(),
            inner_random_stream_algorithm: CrsAlgorithm::None,
            hash_of_header: ProtectedBinary::empty(),
            hash_of_file_on_disk: ProtectedBinary::empty(),
            binaries: Vec::new(),
            random_stream: CryptoRandomStream::new(CrsAlgorithm::None, &[0]),

            repair_mode: false,
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


pub fn load_kdbx_file<PathRef: AsRef<Path>>(p: PathRef, format: KdbxFormat, database: &mut PwDatabase) -> Result<(), Error> {
    let file = std::fs::File::open(p).map_err(|e| Error::IO(e))?;
    let mut buffered = BufReader::new(file);
    load_kdbx(&mut buffered, format, database)
}

pub fn load_kdbx<R: Read>(input: &mut R, format: KdbxFormat, database: &mut PwDatabase) -> Result<(), Error> {
    let mut kdbx = Kdbx::new();

    let mut input = ioutil::ReadInto::new(input, Sha256::new());

    if format == KdbxFormat::PlainXml {
        // This is unencrypted so it doesn't contain any of the encryption headers.
        return load_kdbx_unencrypted(&mut input, database, &mut kdbx);
    }

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

        kdbx.random_stream = CryptoRandomStream::new(kdbx.inner_random_stream_algorithm, &kdbx.inner_random_stream_key);
        let mut decrypt_transform = cipher_engine.decrypt_stream(cipherkey, cipheriv);
        let mut decrypt_stream = TransformRead::new(&mut input, &mut *decrypt_transform);

        // Check that the decryption was successful by checking the first 32 bytes:
        let mut start_stream_bytes = [0u8; 32];
        decrypt_stream.read_exact(&mut start_stream_bytes[0..32]).map_err(|e| Error::IO(e))?;
        if start_stream_bytes != &kdbx.stream_start_bytes[0..32] {
            return Err(Error::BadFormat("File corrupted (bad start bytes)"));
        }
        let mut block_stream = HashedBlockRead::new(&mut decrypt_stream, true);

        match database.compression_algorithm {
            PwCompressionAlgorithm::None => load_kdbx_unencrypted(&mut block_stream, database, &mut kdbx)?,
            PwCompressionAlgorithm::GZip => {
                let mut gz_decode_stream = GzDecoder::new(&mut block_stream);
                load_kdbx_unencrypted(&mut gz_decode_stream, database, &mut kdbx)?
            },
        }
    } else {
        // KDBX >= 4
        unimplemented!("kdbx.version >= 4 decryption no yet implemented");
    }


    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KdbContext {
    Null,
    KeePassFile,
    Meta,
    Root,
    MemoryProtection,
    CustomIcons,
    CustomIcon,
    Binaries,
    CustomData,
    CustomDataItem,
    RootDeletedObjects,
    DeletedObject,
    Group,
    GroupTimes,
    GroupCustomData,
    GroupCustomDataItem,
    Entry,
    EntryTimes,
    EntryString,
    EntryBinary,
    EntryAutoType,
    EntryAutoTypeItem,
    EntryHistory,
    EntryCustomData,
    EntryCustomDataItem
}

struct XmlStartElement {
    name: xml::name::OwnedName,
    attributes: Vec<xml::attribute::OwnedAttribute>,
}

struct XmlEndElement {
    name: xml::name::OwnedName,
}

pub fn load_kdbx_unencrypted<R: Read>(input: &mut R, database: &mut PwDatabase, kdbx: &mut Kdbx) -> Result<(), Error> {
    let mut ctx = KdbContext::Null;
    let config = xml::ParserConfig::new()
            .trim_whitespace(true)
            .ignore_comments(true)
            .coalesce_characters(true);
    let mut xml = EventReader::new_with_config(input, config);

    loop {
        let event = match xml.next() {
            Ok(event_ok) => event_ok,
            Err(_) => {
                return Err(Error::XmlError);
            },
        };

        match event {
            XmlEvent::StartElement { name, attributes, .. } => {
                println!("- start element with context: {:?}", ctx);
                ctx = read_start_xml_element(database, kdbx, ctx, &mut xml, XmlStartElement { name, attributes })?;
            },
            XmlEvent::EndElement { .. } => {
                // @TODO handle element close
            },
            XmlEvent::StartDocument { .. } => { /* NOP */ }
            XmlEvent::EndDocument { .. } => { break; }
            elem => {
                println!("element: {:?}", elem);
                return Err(Error::BadFormat("Unexpected XML element."));
            }
        }
    }

    // @TODO return an error instead.
    assert_eq!(KdbContext::Null, ctx, "Bad ending context value");

    Ok(())
}

fn read_start_xml_element<R: Read>(database: &mut PwDatabase, kdbx: &mut Kdbx, ctx: KdbContext, xml: &mut EventReader<R>, elem: XmlStartElement) -> Result<KdbContext, Error> {
    match ctx {
        KdbContext::Null => {
            if elem.name.local_name == ELEM_DOC_NODE {
                return Ok(KdbContext::KeePassFile);
            } else {
                xml_skip_element(xml, &elem)?;
            }
        },
        KdbContext::KeePassFile => {
            if elem.name.local_name == ELEM_META {
                return Ok(KdbContext::Meta);
            } else if elem.name.local_name == ELEM_ROOT {
                return Ok(KdbContext::Root);
            } else {
                xml_skip_element(xml, &elem)?;
            }
        },
        KdbContext::Meta => {
            match elem.name.local_name.as_str() {
                ELEM_GENERATOR => xml_skip_element(xml, &elem)?, // ignore
                ELEM_HEADER_HASH => {
                    let hash = xml_read_string(kdbx, xml, &elem)?;
                    if hash.len() > 0 && kdbx.hash_of_header.len() > 0 && !kdbx.repair_mode {
                        debug_assert!(kdbx.version < FILE_VERSION_32_4);
                        let hash_bytes = base64::decode(hash.as_bytes()).map_err(|_| Error::BadFormat("Invalid Base64."))?;
                        if &hash_bytes[0..] != &kdbx.hash_of_header[0..] {
                            return Err(Error::BadFormat("File corrupted."));
                        }
                    }
                },
                ELEM_SETTINGS_CHANGED => database.settings_changed = xml_read_time(kdbx, xml, &elem)?,
                ELEM_DB_NAME => database.name = xml_read_string(kdbx, xml, &elem)?,
                ELEM_DB_NAME_CHANGED => database.name_changed = xml_read_time(kdbx, xml, &elem)?,
                ELEM_DB_DESC => database.description = xml_read_string(kdbx, xml, &elem)?,
                ELEM_DB_DESC_CHANGED => database.description_changed = xml_read_time(kdbx, xml, &elem)?,
                ELEM_DB_DEFAULT_USER => database.default_username = xml_read_string(kdbx, xml, &elem)?,
                ELEM_DB_DEFAULT_USER_CHANGED => database.default_username_changed = xml_read_time(kdbx, xml, &elem)?,
                ELEM_DB_MNTNC_HISTORY_DAYS => database.maintenance_history_days = xml_read_uint(kdbx, xml, &elem)?,
                _ => {
                }
            }
        },
        _ => {
            return Err(Error::Generic("Unhandled XML Context"));
        }
    }
    return Ok(ctx);
}

/// Reads until this reads the end of the current element. This will also handle skipping any
/// any other elements that are encountered first.
fn xml_skip_element<R: Read>(xml: &mut EventReader<R>, elem: &XmlStartElement) -> Result<(), Error> {
    let mut depth = 0;
    loop {
        match xml.next() {
            Ok(XmlEvent::StartElement { .. }) => {
                depth += 1;
            },

            Ok(XmlEvent::EndElement { name, .. }) => {
                if depth == 0 {
                    if elem.name == name {
                        break;
                    } else {
                        return Err(Error::XmlError);
                    }
                }
                depth -= 1;
            },

            Ok(XmlEvent::EndDocument) => {
                return Err(Error::BadFormat("Unexpected end of XML document."));
            }

            Err(_) => {
                return Err(Error::XmlError);
            },

            _ => { /* NOP */ }
        }
    }
    Ok(())
}

/// Reads the text contents of an XML element.
fn xml_read_contents<R: Read>(xml: &mut EventReader<R>, elem: &XmlStartElement) -> Result<String, Error> {
    let mut depth = 0;
    loop {
        let event = match xml.next() {
            Ok(event_ok) => event_ok,
            Err(_) => {
                return Err(Error::XmlError);
            },
        };

        match event {
            XmlEvent::StartElement {..} => {
                depth += 1;
            },

            XmlEvent::EndElement { name, .. } => {
                if depth == 0 {
                    if name != elem.name {
                        return Err(Error::XmlError);
                    }
                    return Ok(String::new());
                }
                depth -= 1;
            },

            XmlEvent::Characters(text) => {
                if depth == 0 {
                    return Ok(text);
                }
            }

            XmlEvent::EndDocument => {
                return Err(Error::BadFormat("Unexpected end of XML document."));
            }

            _ => { /* NOP */ }
        }
    }
}

fn xml_read_uint<R: Read>(kdbx: &mut Kdbx, xml: &mut EventReader<R>, elem: &XmlStartElement) -> Result<u32, Error> {
    xml_read_string(kdbx, xml, elem)?.parse::<u32>().map_err(|_| Error::BadFormat("Invalid 32-bit integer."))
}

fn xml_read_time<R: Read>(kdbx: &mut Kdbx, xml: &mut EventReader<R>, elem: &XmlStartElement) -> Result<DateTime<Utc>, Error> {
    if kdbx.format == KdbxFormat::Default && kdbx.version >= FILE_VERSION_32_4 {
        let b = xml_read_base64(kdbx, xml, elem, false)?;
        debug_assert!(b.len() == 8, "Expected timestamp to be 8 bytes.");
        let sec = if b.len() < 8 {
            let mut b8 = [0u8; 8];
            (&mut b8[0..b.len()]).copy_from_slice(&b);
            memutil::bytes_to_i64(&b8)
        } else {
            memutil::bytes_to_i64(&b[0..8])
        };
        Ok(DateTime::from_utc(NaiveDateTime::from_timestamp(sec, 0), Utc))
    } else {
        xml_read_string(kdbx, xml, elem)?.parse::<DateTime<Utc>>().map_err(|_| Error::BadFormat("Invalid DateTime"))
    }
}

fn xml_read_string_raw<R: Read>(xml: &mut EventReader<R>, elem: &XmlStartElement) -> Result<String, Error> {
    xml_read_contents(xml, elem)
}

fn xml_read_string<R: Read>(kdbx: &mut Kdbx, xml: &mut EventReader<R>, elem: &XmlStartElement) -> Result<String, Error> {
    if let Some(xb) = xml_process_node(kdbx, xml, elem)? {
        let mut plaintext = Vec::new();
        xb.plaintext_vec(&mut plaintext);
        String::from_utf8(plaintext).map_err(|_| Error::BadFormat("Invalid UTF8 string."))
    } else {
        xml_read_contents(xml, elem)
    }
}

fn xml_read_base64<R: Read>(kdbx: &mut Kdbx, xml: &mut EventReader<R>, elem: &XmlStartElement, raw: bool) -> Result<Vec<u8>, Error> {
    let s = if raw {
        xml_read_string_raw(xml, elem)?
    } else {
        xml_read_string(kdbx, xml, elem)?
    };

    if s.len() == 0 {
        Ok(Vec::new())
    } else {
        base64::decode(s.as_bytes()).map_err(|_| Error::BadFormat("Invalid Base64 data."))
    }
}

fn xml_process_node<R: Read>(kdbx: &mut Kdbx, xml: &mut EventReader<R>, elem: &XmlStartElement) -> Result<Option<XorredBuffer>, Error> {
    let mut protected = false;
    for attr in elem.attributes.iter() {
        if attr.name.local_name == ATTR_PROTECTED && attr.value == VAL_TRUE {
            protected = true;
            break;
        }
    }

    if protected {
        let mut data = xml_read_base64(kdbx, xml, elem, true)?;
        let dlen = data.len();
        data.resize(dlen * 2, 0);
        kdbx.random_stream.get_random_bytes(&mut data[dlen..]);
        Ok(Some(XorredBuffer::wrap(data)))
    } else {
        Ok(None)
    }
}

fn load_inner_header<R: Read>(input: &mut R, database: &mut PwDatabase, kdbx: &mut Kdbx) -> Result<(), Error> {
    let mut buffer: Vec<u8> = Vec::with_capacity(32);
    loop {
        if !read_inner_header_field(input, database, kdbx, &mut buffer)? {
            break
        }
    }
    Ok(())
}

fn read_inner_header_field<R: Read>(input: &mut R, database: &mut PwDatabase, kdbx: &mut Kdbx, buffer: &mut Vec<u8>) -> Result<bool, Error> {
    let field_id = ioutil::io_read_u8(input)?;
    let size = ioutil::io_read_i32(input)?;

    println!("INNER HEADER ITEM: {}, {} ({})", field_id, size, size as usize);

    if size < 0 {
        return Err(Error::BadFormat("File Corrupted (inner header field size)"));
    } else {
        buffer.resize(size as usize, 0);
        input.read_exact(&mut buffer[0..(size as usize)]).map_err(|e| Error::IO(e))?;
    }

    let data = &buffer[0..(size as usize)];

    let mut result = true;

    match KdbxInnerHeaderFieldID::from_bits(field_id) {
        Some(KdbxInnerHeaderFieldID::END_OF_HEADER) => {
            result = false; // returning false indicates the end of the header
        },

        Some(KdbxInnerHeaderFieldID::INNER_RANDOM_STREAM_ID) => {
            let stream_id = memutil::bytes_to_u32(data);
            if let Some(alg) = CrsAlgorithm::from_int(stream_id) {
                kdbx.inner_random_stream_algorithm = alg;
            } else {
                return Err(Error::BadFormat("Unknown stream cipher algorithm."));
            }
            debug_println!("Set InnerRandomStreamID. (inner header)");
        },

        Some(KdbxInnerHeaderFieldID::INNER_RANDOM_STREAM_KEY) => {
            kdbx.inner_random_stream_key = ProtectedBinary::copy_slice(data);
            debug_println!("Set InnerRandomStreamKey. (inner header)");
            database.context.crypto_random.add_entropy(data);
        },

        Some(KdbxInnerHeaderFieldID::BINARY) => {
            debug_println!("Added binary with length: {}", data.len());
            kdbx.binaries.push(ProtectedBinary::copy_slice(data));
        },

        Some(_) => {
            debug_println!("Unhandled Known Inner Header ID: {:b}", field_id);
        },

        _ => {
            debug_println!("Unknown Inner Header ID: {:b}", field_id);
        }
    }

    Ok(result)
}

fn load_header<R: Read>(input: &mut R, database: &mut PwDatabase, kdbx: &mut Kdbx) -> Result<(), Error> {
    let sig1 = ioutil::io_read_u32(input)?;
    let sig2 = ioutil::io_read_u32(input)?;
    let signature = (sig1, sig2);

    if signature == FILE_SIGNATURE_OLD {
        return Err(Error::OldFormat(error::KEEPASS_VERSION_1X));
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

    let mut buffer: Vec<u8> = Vec::with_capacity(32);

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
        size = ioutil::io_read_u16(input)? as i32;
    } else {
        size = ioutil::io_read_i32(input)?;
    }

    if size < 0 {
        return Err(Error::BadFormat("File Corrupted (outer header field size)"));
    } else if size > 0 {
        buffer.resize(size as usize, 0);
        input.read_exact(&mut buffer[0..(size as usize)]).map_err(|e| Error::IO(e))?;
    }

    let data = &buffer[0..(size as usize)];

    let mut result = true;
    match KdbxHeaderFieldID::from_bits(field_id) {
        Some(KdbxHeaderFieldID::END_OF_HEADER) => {
            result = false; // returning false indicates the end of the header
        },

        Some(KdbxHeaderFieldID::CIPHER_ID) => {
            if data.len() != crate::database::UUID_SIZE {
                return Err(Error::BadFormat("Invalid Cipher"));
            } else {
                database.data_cipher_uuid = PwUUID::from_slice(data);
                debug_println!("Set database cipher UUID.");
            }
        },

        Some(KdbxHeaderFieldID::COMPRESSION_FLAGS) => {
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

        Some(KdbxHeaderFieldID::MASTER_SEED) => {
            kdbx.master_seed = ProtectedBinary::copy_slice(data);
            database.context.crypto_random.add_entropy(data);
            debug_println!("Set MasterSeed.");
        },

        // Obsolete; for backwards compatibility only
        Some(KdbxHeaderFieldID::TRANSFORM_SEED) => {
            debug_assert!(kdbx.version < FILE_VERSION_32_4, "New KDBX file is using parameter `TransformSeed` from legacy KDBX versions.");
            let kdf = kdf::KdfEngine::Aes;
            if database.kdf_parameters.kdf_uuid != kdf.uuid() {
                database.kdf_parameters = kdf.default_parameters();
            }
            database.kdf_parameters.dict.set_arr(kdf::aes::PARAM_SEED, data);
            debug_println!("Set TransformSeed.");
        },

        // Obsolete; for backwards compatibility only
        Some(KdbxHeaderFieldID::TRANSFORM_ROUNDS) => {
            debug_assert!(kdbx.version < FILE_VERSION_32_4, "New KDBX file is using parameter `TransformRounds` from legacy KDBX versions.");
            let kdf = kdf::KdfEngine::Aes;
            if database.kdf_parameters.kdf_uuid != kdf.uuid() {
                database.kdf_parameters = kdf.default_parameters();
            }
            database.kdf_parameters.dict.set_u64(kdf::aes::PARAM_ROUNDS, memutil::bytes_to_u64(data));
            debug_println!("Set TransformRounds.");
        },

        Some(KdbxHeaderFieldID::ENCRYPTION_IV) => {
            debug_assert!(kdbx.version < FILE_VERSION_32_4, "New KDBX file is using parameter `EncryptionIV` from legacy KDBX versions.");
            kdbx.encryption_iv = ProtectedBinary::copy_slice(data);
            debug_println!("Set EncryptionIV.");
        },

        Some(KdbxHeaderFieldID::INNER_RANDOM_STREAM_KEY) => {
            debug_assert!(kdbx.version < FILE_VERSION_32_4, "New KDBX file is using parameter `InnerRandomStreamKey` from legacy KDBX versions.");
            kdbx.inner_random_stream_key = ProtectedBinary::copy_slice(data);
            database.context.crypto_random.add_entropy(data);
            debug_println!("Set InnerRandomStreamKey.");
        },

        Some(KdbxHeaderFieldID::STREAM_START_BYTES) => {
            debug_assert!(kdbx.version < FILE_VERSION_32_4, "New KDBX file is using parameter `StreamStartBytes` from legacy KDBX versions.");
            kdbx.stream_start_bytes = ProtectedBinary::copy_slice(data);
            debug_println!("Set StreamStartBytes.");
        },

        Some(KdbxHeaderFieldID::INNER_RANDOM_STREAM_ID) => {
            let stream_id = memutil::bytes_to_u32(data);
            if let Some(alg) = CrsAlgorithm::from_int(stream_id) {
                kdbx.inner_random_stream_algorithm = alg;
            } else {
                return Err(Error::BadFormat("Unknown stream cipher algorithm."));
            }
            debug_println!("Set InnerRandomStreamID");
        },

        Some(KdbxHeaderFieldID::KDF_PARAMETERS) => {
            database.kdf_parameters.clear();
            kdf::KdfParameters::deserialize(&mut database.kdf_parameters, data)?;
            debug_println!("Set KdfParameters");
        },

        Some(KdbxHeaderFieldID::PUBLIC_CUSTOM_DATA) => {
            debug_assert!(database.public_custom_data.len() == 0, "Public custom data was not empty.");
            database.public_custom_data.clear();
            crate::vdict::VariantDict::deserialize(&mut database.public_custom_data, data)?;
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
