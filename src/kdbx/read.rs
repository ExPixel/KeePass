use std::rc::Rc;
use std::cell::RefCell;
use std::io::prelude::*;
use chrono::prelude::*;
use std::io::BufReader;
use std::path::Path;
use sha2::{Sha256, Sha512, Digest as _};
use flate2::read::GzDecoder;
use xml::reader::{EventReader, XmlEvent};

use crate::error::{self, Error};
use crate::database::{PwDatabase, PwCustomIcon, PwEntry, PwGroup, PwUUID, PwIcon, PwCompressionAlgorithm, PwDeletedObject, AutoTypeObfuscationOptions, AutoTypeAssociation};
use crate::memutil;
use crate::security::{ProtectedBinary, ProtectedString, XorredBuffer};
use crate::ioutil::{self, StoredReadRef};
use crate::strutil;
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
    detach_binaries: Option<String>,

    custom_icon_id: PwUUID,
    custom_icon_data: Vec<u8>,
    custom_data_key: Option<String>,
    custom_data_value: Option<String>,
    ctx_groups: Vec<Rc<RefCell<PwGroup>>>,
    ctx_entry: Option<Rc<RefCell<PwEntry>>>,
    ctx_history_base: Option<Rc<RefCell<PwEntry>>>,
    ctx_string_name: Option<String>,
    ctx_string_value: Option<ProtectedString>,
    ctx_binary_name: Option<String>,
    ctx_binary_value: Option<ProtectedBinary>,
    ctx_deleted_object: Option<PwDeletedObject>,
    entry_in_history: bool,
    group_custom_data_key: Option<String>,
    group_custom_data_value: Option<String>,
    entry_custom_data_key: Option<String>,
    entry_custom_data_value: Option<String>,
    ctx_at_name: Option<String>,
    ctx_at_seq: Option<String>,
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
            detach_binaries: None,

            custom_icon_id: PwUUID::zero(),
            custom_icon_data: Vec::new(),
            custom_data_key: None,
            custom_data_value: None,
            group_custom_data_key: None,
            group_custom_data_value: None,
            entry_custom_data_key: None,
            entry_custom_data_value: None,
            ctx_groups: Vec::new(),
            ctx_entry: None,
            ctx_history_base: None,
            ctx_string_name: None,
            ctx_string_value: None,
            ctx_binary_name: None,
            ctx_binary_value: None,
            ctx_at_name: None,
            ctx_at_seq: None,
            ctx_deleted_object: None,
            entry_in_history: false,
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


pub fn load_kdbx_file<PathRef: AsRef<Path>>(p: PathRef, format: KdbxFormat, database: &mut PwDatabase, kdbx: &mut Kdbx) -> Result<(), Error> {
    let file = std::fs::File::open(p).map_err(|e| Error::IO(e))?;
    let mut buffered = BufReader::new(file);
    load_kdbx(&mut buffered, format, database, kdbx)
}

pub fn load_kdbx<R: Read>(input: &mut R, format: KdbxFormat, database: &mut PwDatabase, kdbx: &mut Kdbx) -> Result<(), Error> {
    let mut input = ioutil::ReadInto::new(input, Sha256::new());

    if format == KdbxFormat::PlainXml {
        // This is unencrypted so it doesn't contain any of the encryption headers.
        return load_kdbx_unencrypted(&mut input, database, kdbx);
    }

    let header_data = {
        let mut stored_input = ioutil::StoredReadRef::new(&mut input);
        load_header(&mut stored_input, database, kdbx)?;
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
            PwCompressionAlgorithm::None => load_kdbx_unencrypted(&mut block_stream, database, kdbx)?,
            PwCompressionAlgorithm::GZip => {
                let mut gz_decode_stream = GzDecoder::new(&mut block_stream);
                load_kdbx_unencrypted(&mut gz_decode_stream, database, kdbx)?
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

impl XmlStartElement {
    #[inline(always)]
    pub fn is_name(&self, name: &str) -> bool {
        self.name.local_name.as_str() == name
    }
}

struct XmlEndElement {
    name: xml::name::OwnedName,
}

impl XmlEndElement {
    #[inline(always)]
    pub fn is_name(&self, name: &str) -> bool {
        self.name.local_name.as_str() == name
    }
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
                debug_println!("Start element `{}` with context: {:?}", name.local_name, ctx);
                ctx = read_start_xml_element(database, kdbx, ctx, &mut xml, XmlStartElement { name, attributes })?;
            },
            XmlEvent::EndElement { name, .. } => {
                debug_println!("End element `{}` with context: {:?}", name.local_name, ctx);
                ctx = read_end_xml_element(database, kdbx, ctx, &mut xml, XmlEndElement { name })?;
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
    assert_eq!(0, kdbx.ctx_groups.len(), "Ended with open groups.");

    Ok(())
}

fn read_start_xml_element<R: Read>(database: &mut PwDatabase, kdbx: &mut Kdbx, ctx: KdbContext, xml: &mut EventReader<R>, elem: XmlStartElement) -> Result<KdbContext, Error> {
    match ctx {
        KdbContext::Null => {
            if elem.name.local_name == ELEM_DOC_NODE {
                return Ok(KdbContext::KeePassFile);
            } else {
                xml_read_unknown(kdbx, xml, &elem)?;
            }
        },
        KdbContext::KeePassFile => {
            if elem.name.local_name == ELEM_META {
                return Ok(KdbContext::Meta);
            } else if elem.name.local_name == ELEM_ROOT {
                return Ok(KdbContext::Root);
            } else {
                xml_read_unknown(kdbx, xml, &elem)?;
            }
        },
        KdbContext::Meta => {
            debug_println!("Reading tag in meta context: {}", elem.name.local_name);
            match elem.name.local_name.as_str() {
                ELEM_GENERATOR => xml_read_unknown(kdbx, xml, &elem)?, // ignore
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
                ELEM_DB_MNTNC_HISTORY_DAYS => database.maintenance_history_days = xml_read_uint(kdbx, xml, &elem)?.unwrap_or(365),
                ELEM_DB_COLOR => {
                     let color_string = xml_read_string(kdbx, xml, &elem)?;
                     database.color = memutil::parse_hex_color(&color_string).map_err(|_| Error::BadFormat("Invalid hex color."))?;
                },
                ELEM_DB_KEY_CHANGED => database.master_key_changed = xml_read_time(kdbx, xml, &elem)?,
                ELEM_DB_KEY_CHANGE_REC => database.master_key_change_rec = xml_read_long(kdbx, xml, &elem)?.unwrap_or(-1),
                ELEM_DB_KEY_CHANGE_FORCE => database.master_key_change_force = xml_read_long(kdbx, xml, &elem)?.unwrap_or(-1),
                ELEM_DB_KEY_CHANGE_FORCE_ONCE => database.master_key_change_force_once = xml_read_bool(kdbx, xml, &elem)?.unwrap_or(false),
                ELEM_MEMORY_PROT => return Ok(KdbContext::MemoryProtection),
                ELEM_CUSTOM_ICONS => return Ok(KdbContext::CustomIcons),
                ELEM_RECYCLE_BIN_ENABLED => database.recycle_bin_enabled = xml_read_bool(kdbx, xml, &elem)?.unwrap_or(true),
                ELEM_RECYCLE_BIN_UUID => database.recycle_bin_uuid = xml_read_uuid(kdbx, xml, &elem)?,
                ELEM_RECYCLE_BIN_CHANGED => database.recycle_bin_changed = xml_read_time(kdbx, xml, &elem)?,
                ELEM_ENTRY_TEMPLATES_GROUP => database.entry_templates_group = xml_read_uuid(kdbx, xml, &elem)?,
                ELEM_ENTRY_TEMPLATES_GROUP_CHANGED => database.entry_templates_group_changed = xml_read_time(kdbx, xml, &elem)?,
                ELEM_HISTORY_MAX_ITEMS => database.history_max_items = xml_read_int(kdbx, xml, &elem)?.unwrap_or(-1),
                ELEM_HISTORY_MAX_SIZE => database.history_max_size = xml_read_long(kdbx, xml, &elem)?.unwrap_or(-1),
                ELEM_LAST_SELECTED_GROUP => database.last_selected_group = xml_read_uuid(kdbx, xml, &elem)?,
                ELEM_LAST_TOP_VISIBLE_GROUP => database.last_top_visible_group = xml_read_uuid(kdbx, xml, &elem)?,
                ELEM_BINARIES => return Ok(KdbContext::Binaries),
                ELEM_CUSTOM_DATA => return Ok(KdbContext::CustomData),
                _ => {
                    xml_read_unknown(kdbx, xml, &elem)?
                }
            }
        },
        KdbContext::MemoryProtection => {
            match elem.name.local_name.as_str() {
                ELEM_PROT_TITLE => database.memory_protection.protect_title = xml_read_bool(kdbx, xml, &elem)?.unwrap_or(false),
                ELEM_PROT_USER_NAME =>database.memory_protection.protect_username = xml_read_bool(kdbx, xml, &elem)?.unwrap_or(false),
                ELEM_PROT_PASSWORD => database.memory_protection.protect_password = xml_read_bool(kdbx, xml, &elem)?.unwrap_or(true),
                ELEM_PROT_URL => database.memory_protection.protect_url = xml_read_bool(kdbx, xml, &elem)?.unwrap_or(false),
                ELEM_PROT_NOTES => database.memory_protection.protect_notes = xml_read_bool(kdbx, xml, &elem)?.unwrap_or(false),

                _ => xml_read_unknown(kdbx, xml, &elem)?,
            }
        },
        KdbContext::CustomIcons => {
            if elem.is_name(ELEM_CUSTOM_ICONS) {
                return Ok(KdbContext::CustomIcon);
            } else {
                xml_read_unknown(kdbx, xml, &elem)?
            }
        },
        KdbContext::CustomIcon => {
            if elem.is_name(ELEM_CUSTOM_ICON_ITEM_ID) {
                kdbx.custom_icon_id = xml_read_uuid(kdbx, xml, &elem)?;
            } else if elem.is_name(ELEM_CUSTOM_ICON_ITEM_DATA) {
                let data = xml_read_string(kdbx, xml, &elem)?;
                debug_assert!(data.len() > 0, "Empty custom icon data.");
                if data.len() > 0 {
                    kdbx.custom_icon_data = base64::decode(data.as_bytes()).map_err(|_| Error::BadFormat("Invalid Base64 data."))?;
                }
            } else {
                xml_read_unknown(kdbx, xml, &elem)?
            }
        },
        KdbContext::Binaries => {
            if elem.is_name(ELEM_BINARY) {
                let maybe_attr_id = elem.attributes.iter().find(|attr| attr.name.local_name == ATTR_ID);
                if let Some(attr_id) = maybe_attr_id {
                    let key = attr_id.value.parse::<usize>().map_err(|_| Error::BadFormat("Invalid binary index."))?;

                    kdbx.binaries.resize_with(key + 1, || ProtectedBinary::empty());
                    kdbx.binaries[key] = xml_read_protected_binary(kdbx, xml, &elem)?;
                } else {
                    xml_read_unknown(kdbx, xml, &elem)?
                }
            } else {
                xml_read_unknown(kdbx, xml, &elem)?
            }
        },
        KdbContext::CustomData => {
            if elem.is_name(ELEM_STRING_DICT_EX_ITEM) {
                return Ok(KdbContext::CustomDataItem);
            } else {
                xml_read_unknown(kdbx, xml, &elem)?
            }
        },
        KdbContext::CustomDataItem => {
            if elem.is_name(ELEM_KEY) {
                kdbx.custom_data_key = Some(xml_read_string(kdbx, xml, &elem)?);
            } else if elem.is_name(ELEM_VALUE) {
                kdbx.custom_data_value = Some(xml_read_string(kdbx, xml, &elem)?);
            } else {
                xml_read_unknown(kdbx, xml, &elem)?
            }
        },
        KdbContext::Root => {
            if elem.is_name(ELEM_GROUP) {
                debug_assert!(kdbx.ctx_groups.len() == 0, "Context groups already populated.");
                if kdbx.ctx_groups.len() != 0 {
                    return Err(Error::BadFormat("Context groups already populated."));
                }
                database.root_group = PwGroup::default().wrap();
                kdbx.ctx_groups.push(Rc::clone(&database.root_group));
                return Ok(KdbContext::Group);
            } else if elem.is_name(ELEM_DELETED_OBJECTS) {
                return Ok(KdbContext::RootDeletedObjects);
            } else {
                xml_read_unknown(kdbx, xml, &elem)?
            }
        },
        KdbContext::Group => {
            if let Some(group) = kdbx.ctx_groups.last().map(Rc::clone) {
                match elem.name.local_name.as_str() {
                    ELEM_UUID => group.borrow_mut().uuid = xml_read_uuid(kdbx, xml, &elem)?,
                    ELEM_NAME => group.borrow_mut().name = xml_read_string(kdbx, xml, &elem)?,
                    ELEM_NOTES => group.borrow_mut().notes = xml_read_string(kdbx, xml, &elem)?,
                    ELEM_ICON => group.borrow_mut().icon = xml_read_icon_id(kdbx, xml, &elem)?.unwrap_or(PwIcon::Folder),
                    ELEM_CUSTOM_ICON_ID => group.borrow_mut().custom_icon_uuid = xml_read_uuid(kdbx, xml, &elem)?,
                    ELEM_TIMES => return Ok(KdbContext::GroupTimes),
                    ELEM_IS_EXPANDED => group.borrow_mut().is_expanded = xml_read_bool(kdbx, xml, &elem)?.unwrap_or(true),
                    ELEM_GROUP_DEFAULT_AUTO_TYPE_SEQ => group.borrow_mut().default_autotype_sequence = xml_read_string(kdbx, xml, &elem)?,
                    ELEM_ENABLE_AUTO_TYPE => group.borrow_mut().enable_autotype = strutil::string_to_bool_ex(&xml_read_string(kdbx, xml, &elem)?),
                    ELEM_ENABLE_SEARCHING => group.borrow_mut().enable_searching = strutil::string_to_bool_ex(&xml_read_string(kdbx, xml, &elem)?),
                    ELEM_LAST_TOP_VISIBLE_ENTRY => group.borrow_mut().last_top_visible_entry = xml_read_uuid(kdbx, xml, &elem)?,
                    ELEM_CUSTOM_DATA => return Ok(KdbContext::GroupCustomData),
                    ELEM_GROUP => {
                        let sub_group = PwGroup::default().wrap();
                        PwGroup::add_group(&group, Rc::clone(&sub_group), true, false);
                        kdbx.ctx_groups.push(sub_group);
                        return Ok(KdbContext::Group);
                    },
                    ELEM_ENTRY => {
                        let entry = PwEntry::default().wrap();
                        if let Some(ref mut group) = kdbx.ctx_groups.last() {
                            PwGroup::add_entry(&group, Rc::clone(&entry), true, false);
                        } else {
                            return Err(Error::BadFormat("No group for KDBX entry."));
                        }
                        kdbx.ctx_entry = Some(entry);
                        return Ok(KdbContext::Entry);
                    },
                    _ => xml_read_unknown(kdbx, xml, &elem)?,
                }
            } else {
                // @TODO this should probably be an error but it doesn't seem to even be a
                // consideration in the original C# implementation.
                debug_assert!(false, "No group set.");
                xml_read_unknown(kdbx, xml, &elem)?
            }
        }
        KdbContext::GroupCustomData => {
            if elem.is_name(ELEM_STRING_DICT_EX_ITEM) {
                return Ok(KdbContext::GroupCustomDataItem);
            } else {
                xml_read_unknown(kdbx, xml, &elem)?
            }
        },
        KdbContext::GroupCustomDataItem => {
            if elem.is_name(ELEM_KEY) {
                kdbx.group_custom_data_key = Some(xml_read_string(kdbx, xml, &elem)?);
            } else if elem.is_name(ELEM_VALUE) {
                kdbx.group_custom_data_value = Some(xml_read_string(kdbx, xml, &elem)?);
            } else {
                xml_read_unknown(kdbx, xml, &elem)?
            }
        },
        KdbContext::Entry => {
            if let Some(entry_cell) = kdbx.ctx_entry.as_ref().map(Rc::clone) {
                let mut entry = entry_cell.borrow_mut();
                match elem.name.local_name.as_str() {
                    ELEM_UUID => entry.uuid = xml_read_uuid(kdbx, xml, &elem)?,
                    ELEM_ICON => entry.icon = xml_read_icon_id(kdbx, xml, &elem)?.unwrap_or(PwIcon::Key),
                    ELEM_CUSTOM_ICON_ID => entry.custom_icon_uuid = xml_read_uuid(kdbx, xml, &elem)?,
                    ELEM_FG_COLOR => {
                        // @TODO this should parse actual HTML color values
                        entry.foreground_color = memutil::parse_hex_color(&(xml_read_string(kdbx, xml, &elem)?)).unwrap_or((0, 0, 0, 0));
                    },
                    ELEM_BG_COLOR => {
                        // @TODO this should parse actual HTML color values
                        entry.background_color = memutil::parse_hex_color(&(xml_read_string(kdbx, xml, &elem)?)).unwrap_or((0, 0, 0, 0));
                    },
                    ELEM_OVERRIDE_URL => {
                        entry.override_url = xml_read_string(kdbx, xml, &elem)?;
                    },
                    ELEM_TAGS => {
                        entry.tags = strutil::string_to_tags(&xml_read_string(kdbx, xml, &elem)?);
                    },
                    ELEM_TIMES => {
                        return Ok(KdbContext::EntryTimes);
                    },
                    ELEM_STRING => {
                        return Ok(KdbContext::EntryString);
                    },
                    ELEM_BINARY => {
                        return Ok(KdbContext::EntryBinary);
                    },
                    ELEM_AUTO_TYPE => {
                        return Ok(KdbContext::EntryAutoType);
                    },
                    ELEM_CUSTOM_DATA => {
                        return Ok(KdbContext::EntryCustomData);
                    },
                    ELEM_HISTORY => {
                        debug_assert!(!kdbx.entry_in_history, "Entry is already in history.");

                        if !kdbx.entry_in_history {
                            kdbx.ctx_history_base = kdbx.ctx_entry.as_ref().map(|e| Rc::clone(e));
                            return Ok(KdbContext::EntryHistory);
                        } else {
                            xml_read_unknown(kdbx, xml, &elem)?
                        }
                    },
                    _ => xml_read_unknown(kdbx, xml, &elem)?,
                }
            }
        },
        KdbContext::GroupTimes => {
            if let Some(group_cell) = kdbx.ctx_groups.last().map(Rc::clone) {
                let mut group = group_cell.borrow_mut();
                match elem.name.local_name.as_str() {
                    ELEM_CREATION_TIME => group.creation_time = xml_read_time(kdbx, xml, &elem)?,
                    ELEM_LAST_MOD_TIME => group.last_modification_time = xml_read_time(kdbx, xml, &elem)?,
                    ELEM_LAST_ACCESS_TIME => group.last_access_time = xml_read_time(kdbx, xml, &elem)?,
                    ELEM_EXPIRY_TIME => group.expiry_time = xml_read_time(kdbx, xml, &elem)?,
                    ELEM_EXPIRES => group.expires = xml_read_bool(kdbx, xml, &elem)?.unwrap_or(false),
                    ELEM_USAGE_COUNT => group.usage_count = xml_read_ulong(kdbx, xml, &elem)?.unwrap_or(0),
                    ELEM_LOCATION_CHANGED => group.location_changed = xml_read_time(kdbx, xml, &elem)?,
                    _ => xml_read_unknown(kdbx, xml, &elem)?,
                }
            } else {
                debug_assert!(false, "No group for times.");
                xml_read_unknown(kdbx, xml, &elem)?
            }
        },
        KdbContext::EntryTimes => {
            if let Some(entry_cell) = kdbx.ctx_entry.as_ref().map(Rc::clone) {
                let mut entry = entry_cell.borrow_mut();
                match elem.name.local_name.as_str() {
                    ELEM_CREATION_TIME => entry.creation_time = xml_read_time(kdbx, xml, &elem)?,
                    ELEM_LAST_MOD_TIME => entry.last_modification_time = xml_read_time(kdbx, xml, &elem)?,
                    ELEM_LAST_ACCESS_TIME => entry.last_access_time = xml_read_time(kdbx, xml, &elem)?,
                    ELEM_EXPIRY_TIME => entry.expiry_time = xml_read_time(kdbx, xml, &elem)?,
                    ELEM_EXPIRES => entry.expires = xml_read_bool(kdbx, xml, &elem)?.unwrap_or(false),
                    ELEM_USAGE_COUNT => entry.usage_count = xml_read_ulong(kdbx, xml, &elem)?.unwrap_or(0),
                    ELEM_LOCATION_CHANGED => entry.location_changed = xml_read_time(kdbx, xml, &elem)?,
                    _ => xml_read_unknown(kdbx, xml, &elem)?,
                }
            } else {
                debug_assert!(false, "No entry for times.");
                xml_read_unknown(kdbx, xml, &elem)?
            }
        },
        KdbContext::EntryString => {
            if elem.is_name(ELEM_KEY) {
                kdbx.ctx_string_name = Some(xml_read_string(kdbx, xml, &elem)?);
            } else if elem.is_name(ELEM_VALUE) {
                kdbx.ctx_string_value = Some(xml_read_protected_string(kdbx, xml, &elem)?);
            } else {
                xml_read_unknown(kdbx, xml, &elem)?
            }
        },
        KdbContext::EntryBinary => {
            if elem.is_name(ELEM_KEY) {
                kdbx.ctx_binary_name = Some(xml_read_string(kdbx, xml, &elem)?);
            } else if elem.is_name(ELEM_VALUE) {
                kdbx.ctx_binary_value = Some(xml_read_protected_binary(kdbx, xml, &elem)?);
            } else {
                xml_read_unknown(kdbx, xml, &elem)?
            }
        },
        KdbContext::EntryAutoType => {
            match elem.name.local_name.as_str() {
                ELEM_AUTO_TYPE_ENABLED => {
                    let v = xml_read_bool(kdbx, xml, &elem)?.unwrap_or(true);
                    kdbx.ctx_entry.as_ref().map(|e| e.borrow_mut().auto_type.enabled = v).ok_or(Error::BadFormat("No entry for field."))?;
                },
                ELEM_AUTO_TYPE_OBFUSCATION => {
                    let v = AutoTypeObfuscationOptions::from_int(xml_read_uint(kdbx, xml, &elem)?.unwrap_or(0)).unwrap_or(AutoTypeObfuscationOptions::None);
                    kdbx.ctx_entry.as_ref().map(|e| e.borrow_mut().auto_type.obfuscation_options = v).ok_or(Error::BadFormat("No entry for field."))?;
                },
                ELEM_AUTO_TYPE_DEFAULT_SEQ => {
                    let v = xml_read_string(kdbx, xml, &elem)?;
                    kdbx.ctx_entry.as_ref().map(|e| e.borrow_mut().auto_type.default_sequence = v).ok_or(Error::BadFormat("No entry for field."))?;
                },
                ELEM_AUTO_TYPE_ITEM => {
                    return Ok(KdbContext::EntryAutoTypeItem);
                },
                _ => xml_read_unknown(kdbx, xml, &elem)?
            }
        },
        KdbContext::EntryAutoTypeItem => {
            if elem.is_name(ELEM_WINDOW) {
                kdbx.ctx_at_name = Some(xml_read_string(kdbx, xml, &elem)?);
            } else if elem.is_name(ELEM_KEYSTROKE_SEQUENCE) {
                kdbx.ctx_at_seq = Some(xml_read_string(kdbx, xml, &elem)?);
            } else {
                xml_read_unknown(kdbx, xml, &elem)?
            }
        },
        KdbContext::EntryCustomData => {
            if elem.is_name(ELEM_STRING_DICT_EX_ITEM) {
                return Ok(KdbContext::EntryCustomDataItem);
            } else {
                xml_read_unknown(kdbx, xml, &elem)?
            }
        },
        KdbContext::EntryCustomDataItem => {
            if elem.is_name(ELEM_KEY) {
                kdbx.entry_custom_data_key = Some(xml_read_string(kdbx, xml, &elem)?);
            } else if elem.is_name(ELEM_VALUE) {
                kdbx.entry_custom_data_value = Some(xml_read_string(kdbx, xml, &elem)?);
            } else {
                xml_read_unknown(kdbx, xml, &elem)?
            }
        },
        KdbContext::EntryHistory => {
            if elem.is_name(ELEM_ENTRY) {
                let entry = PwEntry::new(None, false, false).wrap();
                if let Some(ref mut history_base) = kdbx.ctx_history_base {
                    history_base.borrow_mut().history.push(Rc::clone(&entry));
                } else {
                    debug_assert!(false, "No history base entry for history item.");
                    return Err(Error::BadFormat("No history base."));
                }
                kdbx.ctx_entry = Some(entry);
                kdbx.entry_in_history = true;
                return Ok(KdbContext::Entry);
            } else {
                xml_read_unknown(kdbx, xml, &elem)?
            }
        },
        KdbContext::RootDeletedObjects => {
            if elem.is_name(ELEM_DELETED_OBJECT) {
                // @NOTE unlike in the original KeePass source, we add the deleted object to the
                // database when the tag is closed instead of when it is opened.
                kdbx.ctx_deleted_object = Some(PwDeletedObject::default());
            } else {
                xml_read_unknown(kdbx, xml, &elem)?
            }
        },
        KdbContext::DeletedObject => {
            if elem.is_name(ELEM_UUID) {
                let uuid = xml_read_uuid(kdbx, xml, &elem)?;
                kdbx.ctx_deleted_object.as_mut().map(|d| d.uuid = uuid).ok_or(Error::BadFormat("No deleted object."))?;
            } else if elem.is_name(ELEM_DELETION_TIME) {
                let time = xml_read_time(kdbx, xml, &elem)?;
                kdbx.ctx_deleted_object.as_mut().map(|d| d.deletion_time = time).ok_or(Error::BadFormat("No deleted object."))?;
            } else {
                xml_read_unknown(kdbx, xml, &elem)?
            }
        },
    }
    return Ok(ctx);
}

fn read_end_xml_element<R: Read>(database: &mut PwDatabase, kdbx: &mut Kdbx, ctx: KdbContext, _xml: &mut EventReader<R>, elem: XmlEndElement) -> Result<KdbContext, Error> {
    match (ctx, elem.name.local_name.as_str()) {
        (KdbContext::KeePassFile, ELEM_DOC_NODE) =>  return Ok(KdbContext::Null),
        (KdbContext::Meta, ELEM_META) =>  return Ok(KdbContext::KeePassFile),
        (KdbContext::Root, ELEM_ROOT) =>  return Ok(KdbContext::KeePassFile),
        (KdbContext::MemoryProtection, ELEM_MEMORY_PROT) =>  return Ok(KdbContext::Meta),
        (KdbContext::CustomIcons, ELEM_CUSTOM_ICONS) => return Ok(KdbContext::Meta),
        (KdbContext::CustomIcon, ELEM_CUSTOM_ICON_ITEM) => {
            if kdbx.custom_icon_id == PwUUID::ZERO && kdbx.custom_icon_data.len() > 0 {
                database.custom_icons.push(
                    PwCustomIcon::new(
                        std::mem::replace(&mut kdbx.custom_icon_id, PwUUID::ZERO),
                        std::mem::replace(&mut kdbx.custom_icon_data, Vec::new())
                    )
                );
                return Ok(KdbContext::CustomIcons);
            } else {
                return Err(Error::BadFormat("Empty custom icon."));
            }
        },
        (KdbContext::Binaries, ELEM_BINARIES) => return Ok(KdbContext::Meta),
        (KdbContext::CustomData, ELEM_CUSTOM_DATA) => return Ok(KdbContext::Meta),
        (KdbContext::CustomDataItem, ELEM_STRING_DICT_EX_ITEM) => {
            if let (Some(key), Some(value)) = (kdbx.custom_data_key.take(), kdbx.custom_data_value.take()) {
                database.custom_data.insert(key, value);
            } else {
                debug_assert!(false, "No custom data key and/or custom data value.");
            }
            return Ok(KdbContext::CustomData);
        }
        (KdbContext::Group, ELEM_GROUP) => {
            if let Some(group_cell) = kdbx.ctx_groups.pop() {
                let mut group = group_cell.borrow_mut();
                if group.uuid.is_zero() {
                    group.uuid = PwUUID::random();
                }
            } else {
                debug_assert!(false, "No group D:");
            }

            if kdbx.ctx_groups.len() > 0 {
                return Ok(KdbContext::Group);
            } else {
                return Ok(KdbContext::Root);
            }
        },
        (KdbContext::GroupTimes, ELEM_TIMES) => return Ok(KdbContext::Group),
        (KdbContext::GroupCustomData, ELEM_CUSTOM_DATA) => return Ok(KdbContext::Group),
        (KdbContext::GroupCustomDataItem, ELEM_STRING_DICT_EX_ITEM) =>  {
            if let (Some(key), Some(value)) = (kdbx.group_custom_data_key.take(), kdbx.group_custom_data_value.take()) {
                if let Some(ref mut group_cell) = kdbx.ctx_groups.last() {
                    let mut group = group_cell.borrow_mut();
                    group.custom_data.insert(key, value);
                } else {
                    debug_assert!(false, "Expected a group here.");
                }
            } else {
                debug_assert!(false, "No group custom data key and/or custom data value.");
            }
            return Ok(KdbContext::GroupCustomData);
        },
        (KdbContext::Entry, ELEM_ENTRY) => {
            if let Some(ref mut entry_cell) = kdbx.ctx_entry {
                let mut entry = entry_cell.borrow_mut();
                if entry.uuid.is_zero() {
                    entry.uuid = PwUUID::random();
                }
            }

            if kdbx.entry_in_history {
                kdbx.ctx_entry = kdbx.ctx_history_base.as_ref().map(Rc::clone);
                return Ok(KdbContext::EntryHistory);
            }

            return Ok(KdbContext::Group);
        },
        (KdbContext::EntryTimes, ELEM_TIMES) => return Ok(KdbContext::Entry),
        (KdbContext::EntryString, ELEM_STRING) => {
            if let (Some(name), Some(value)) = (kdbx.ctx_string_name.take(), kdbx.ctx_string_value.take()) {
                if let Some(ref mut entry_cell) = kdbx.ctx_entry {
                    let mut entry = entry_cell.borrow_mut();
                    entry.strings.insert(name, value);
                } else {
                    return Err(Error::BadFormat("No entry for string name/value."));
                }
            } else {
                return Err(Error::BadFormat("End of string with no name/value."));
            }
            return Ok(KdbContext::Entry);
        },
        (KdbContext::EntryBinary, ELEM_BINARY) => {
            if let (Some(name), Some(value)) = (kdbx.ctx_binary_name.take(), kdbx.ctx_binary_value.take()) {
                if kdbx.detach_binaries.as_ref().map(|d| d.len()).unwrap_or(0) == 0 {
                    if let Some(ref mut entry_cell) = kdbx.ctx_entry {
                        let mut entry = entry_cell.borrow_mut();
                        entry.binaries.insert(name, value);
                    } else {
                        return Err(Error::BadFormat("No entry for binary."));
                    }
                } else {
                    unimplemented!("SaveBinary is not yet implemented");
                }
            } else {
                return Err(Error::BadFormat("End of binary with no name/value."));
            }
            return Ok(KdbContext::Entry);
        },
        (KdbContext::EntryAutoType, ELEM_AUTO_TYPE) => return Ok(KdbContext::Entry),
        (KdbContext::EntryAutoTypeItem, ELEM_AUTO_TYPE_ITEM) => {
            if let (Some(at_name), Some(at_seq)) = (kdbx.ctx_at_name.take(), kdbx.ctx_at_seq.take()) {
                let at_assoc = AutoTypeAssociation::new(at_name, at_seq);
                kdbx.ctx_entry
                    .as_ref()
                    .map(|e| e.borrow_mut())
                    .map(|mut e| e.auto_type.add(at_assoc))
                    .ok_or(Error::BadFormat("No entry for auto type item."))?;
                return Ok(KdbContext::EntryAutoType);
            } else {
                return Err(Error::BadFormat("End of AutoTypeItem with no name/seq"));
            }
        },
        (KdbContext::EntryCustomData, ELEM_CUSTOM_DATA) => return Ok(KdbContext::Entry),
        (KdbContext::EntryCustomDataItem, ELEM_STRING_DICT_EX_ITEM) => {
            if let (Some(key), Some(val)) = (kdbx.entry_custom_data_key.take(), kdbx.entry_custom_data_value.take()) {
                kdbx.ctx_entry
                    .as_ref()
                    .map(|e| e.borrow_mut())
                    .map(|mut e| e.custom_data.insert(key, val))
                    .ok_or(Error::BadFormat("No entry for custom data item."))?;
                return Ok(KdbContext::EntryCustomData);
            } else {
                return Err(Error::BadFormat("end of entry custom data item with no key/value."));
            }
        }
        (KdbContext::EntryHistory, ELEM_HISTORY) => {
            kdbx.entry_in_history = false;
            return Ok(KdbContext::Entry)
        },
        (KdbContext::RootDeletedObjects, ELEM_DELETED_OBJECTS) => {
            // @NOTE the original KeePass source actually clears this in (DeletedObject, ELEM_DELETED_OBJECT) but it's done here instead.
            if let Some(deleted_object) = kdbx.ctx_deleted_object.take() {
                database.deleted_objects.push(deleted_object);
            }
            return Ok(KdbContext::Root);
        }
        (KdbContext::DeletedObject, ELEM_DELETED_OBJECT) => {
            return Ok(KdbContext::RootDeletedObjects);
        }
        _ => {
            return Err(Error::Generic("Unhandled XML Context (Element End)"));
        }
    }
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

/// Reads the text contents of an XML element. This will also skip past the end of the current
/// element.
fn xml_read_contents<R: Read>(xml: &mut EventReader<R>, elem: &XmlStartElement) -> Result<String, Error> {
    let mut depth = 0;
    let mut contents = String::new();
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
                    break;
                }
                depth -= 1;
            },

            XmlEvent::Characters(text) => {
                if depth == 0 {
                    contents = text;
                    // here we get the contents but we don't actually leave the loop until the end
                    // of the element is reached.
                }
            }

            XmlEvent::EndDocument => {
                return Err(Error::BadFormat("Unexpected end of XML document."));
            }

            _ => { /* NOP */ }
        }
    }

    Ok(contents)
}


// @TODO later it might be better to use dynamic dispatch instead to reduce code bloat by doing the
// following because at the moment a version of all of this code is generated for each type of
// reader :o
// fn xml_read_uuid(kdbx: &mut Kdbx, xml: &mut EventReader<&mut dyn Read>, elem: &XmlStartElement) -> Result<bool, Error> {

fn xml_read_unknown<R: Read>(kdbx: &mut Kdbx, xml: &mut EventReader<R>, elem: &XmlStartElement) -> Result<(), Error> {
    debug_println!("!! Reading Unknown ({})", elem.name.local_name);

    let mut depth = 0i32;

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

                // Reading these keeps the random number generator consistent.
                xml_process_node(kdbx, xml, elem)?;
            },

            XmlEvent::EndElement { name, .. } => {
                if depth == 0 {
                    if elem.name == name {
                        return Ok(())
                    } else {
                        return Err(Error::XmlError);
                    }
                }
                depth -= 1;
            },

            XmlEvent::EndDocument => {
                return Err(Error::BadFormat("Unexpected end of XML document."));
            }

            _ => { /* NOP */ }
        }
    }
}

fn xml_read_protected_binary<R: Read>(kdbx: &mut Kdbx, xml: &mut EventReader<R>, elem: &XmlStartElement) -> Result<ProtectedBinary, Error> {
    let mut maybe_bin_ref: Option<usize> = None;
    let mut compressed: bool = false;
    for attr in elem.attributes.iter() {
        if attr.name.local_name == ATTR_COMPRESSED && attr.value == VAL_TRUE {
            compressed = true;
        }

        if attr.name.local_name == ATTR_REF {
            let index = xml_read_int(kdbx, xml, elem)?.unwrap_or(-1);
            if index < 0 {
                return Err(Error::BadFormat("Invalid binary index."));
            } else {
                maybe_bin_ref = Some(index as usize);
                break;
            }
        }
    }

    if let Some(bin_ref) = maybe_bin_ref {
        if let Some(ref binary) = kdbx.binaries.get(bin_ref) {
            Ok((*binary).clone())
        } else {
            return Err(Error::BadFormat("Invalid binary index."));
        }
    } else {
        if let Some(xb) = xml_process_node(kdbx, xml, elem)? {
            debug_assert!(!compressed, "Binary cannot be encrypted and compressed at the same time.");
            let mut pb_vec = Vec::new();
            xb.plaintext_vec(&mut pb_vec);
            Ok(ProtectedBinary::wrap(pb_vec))
        } else {
            let data = xml_read_base64(kdbx, xml, elem, true)?;
            if data.len() == 0 {
                Ok(ProtectedBinary::empty())
            } else {
                if compressed {
                    Ok(ProtectedBinary::wrap(memutil::decompress(&data)?))
                } else {
                    Ok(ProtectedBinary::wrap(data))
                }
            }
        }
    }
}

fn xml_read_protected_string<R: Read>(kdbx: &mut Kdbx, xml: &mut EventReader<R>, elem: &XmlStartElement) -> Result<ProtectedString, Error> {
    if let Some(buf) = xml_process_node(kdbx, xml, elem)? {
        let mut pbuf = Vec::new();
        buf.plaintext_vec(&mut pbuf);
        Ok(ProtectedString::wrap(String::from_utf8(pbuf).map_err(|_| Error::BadFormat("Invalid UTF8 string."))?))
    } else {
        Ok(ProtectedString::wrap(xml_read_string(kdbx, xml, elem)?))
    }
}
fn xml_read_icon_id<R: Read>(kdbx: &mut Kdbx, xml: &mut EventReader<R>, elem: &XmlStartElement) -> Result<Option<PwIcon>, Error> {
    let i = xml_read_int(kdbx, xml, elem)?.unwrap_or(-1);

    if i > 0 {
        Ok(PwIcon::from_int(i as u32))
    } else {
        Ok(None)
    }
}

fn xml_read_uuid<R: Read>(kdbx: &mut Kdbx, xml: &mut EventReader<R>, elem: &XmlStartElement) -> Result<PwUUID, Error> {
    let b = xml_read_base64(kdbx, xml, elem, false)?;

    // @TODO check if I should be doing this or not. At the moment I just zero extend the buffer if
    // it's too small and truncate it if it's too large.
    if b.len() < PwUUID::SIZE {
        let mut b2 = [0u8; PwUUID::SIZE];
        (&mut b2[0..b.len()]).copy_from_slice(&b);
        Ok(PwUUID::wrap(b2))
    } else {
        Ok(PwUUID::from_slice(&b))
    }
}

fn xml_read_bool<R: Read>(kdbx: &mut Kdbx, xml: &mut EventReader<R>, elem: &XmlStartElement) -> Result<Option<bool>, Error> {
    match (xml_read_string(kdbx, xml, elem)?).as_str() {
        VAL_TRUE => Ok(Some(true)),
        VAL_FALSE => Ok(Some(false)),
        _ => Ok(None),
    }
}

fn xml_read_int<R: Read>(kdbx: &mut Kdbx, xml: &mut EventReader<R>, elem: &XmlStartElement) -> Result<Option<i32>, Error> {
    Ok(xml_read_string(kdbx, xml, elem)?.parse::<i32>().ok())
}

fn xml_read_uint<R: Read>(kdbx: &mut Kdbx, xml: &mut EventReader<R>, elem: &XmlStartElement) -> Result<Option<u32>, Error> {
    Ok(xml_read_string(kdbx, xml, elem)?.parse::<u32>().ok())
}

fn xml_read_long<R: Read>(kdbx: &mut Kdbx, xml: &mut EventReader<R>, elem: &XmlStartElement) -> Result<Option<i64>, Error> {
    Ok(xml_read_string(kdbx, xml, elem)?.parse::<i64>().ok())
}

fn xml_read_ulong<R: Read>(kdbx: &mut Kdbx, xml: &mut EventReader<R>, elem: &XmlStartElement) -> Result<Option<u64>, Error> {
    Ok(xml_read_string(kdbx, xml, elem)?.parse::<u64>().ok())
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
