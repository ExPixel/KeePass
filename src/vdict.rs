use std::collections::HashMap;
use crate::memutil;
use crate::ioutil;
use crate::error::Error;

#[derive(Clone, PartialEq, Debug)]
pub enum DictObject {
    None,
    UInt32(u32),
    UInt64(u64),
    Int32(i32),
    Int64(i64),
    String(String),
    ByteArray(Vec<u8>),
    Bool(bool),
}

#[repr(u8)]
pub enum VdType {
    None = 0,
    // Byte = 0x02,
    // UInt16 = 0x03,
    UInt32 = 0x04,
    UInt64 = 0x05,
    // Signed mask: 0x08
    Bool = 0x08,
    // SByte = 0x0A,
    // Int16 = 0x0B,
    Int32 = 0x0C,
    Int64 = 0x0D,
    // Float = 0x10,
    // Double = 0x11,
    // Decimal = 0x12,

    // Char = 0x17, // 16-bit Unicode Character
    String = 0x18,

    // Array mask: 0x40
    ByteArray = 0x42,
}

impl VdType {
    pub fn type_of(o: &DictObject) -> VdType {
        match o {
            &DictObject::None => VdType::None,
            &DictObject::UInt32(..) => VdType::UInt32,
            &DictObject::UInt64(..) => VdType::UInt64,
            &DictObject::Bool(..) => VdType::Bool,
            &DictObject::Int32(..) => VdType::Int32,
            &DictObject::Int64(..) => VdType::Int64,
            &DictObject::String(..) => VdType::String,
            &DictObject::ByteArray(..) => VdType::ByteArray,
        }
    }

    pub fn from_int(n: u8) -> Option<VdType> {
        match n {
            0x00 => Some(VdType::None),
            0x04 => Some(VdType::UInt32),
            0x05 => Some(VdType::UInt64),
            0x08 => Some(VdType::Bool),
            0x0C => Some(VdType::Int32),
            0x0D => Some(VdType::Int64),
            0x18 => Some(VdType::String),
            0x42 => Some(VdType::ByteArray),
            _ => None,
        }
    }

    pub fn to_int(self) -> u8 {
        match self {
            VdType::None => 0x00,
            VdType::UInt32 => 0x04,
            VdType::UInt64 => 0x05,
            VdType::Bool => 0x08,
            VdType::Int32 => 0x0C,
            VdType::Int64 => 0x0D,
            VdType::String => 0x18,
            VdType::ByteArray => 0x42,
        }
    }
}

#[derive(Clone, Debug)]
pub struct VariantDict {
    inner: HashMap<String, DictObject>,
}

impl VariantDict {
    pub const VD_VERSION: u16   = 0x0100;
    pub const VDM_CRITICAL: u16 = 0xFF00;
    pub const VDM_INFO: u16     = 0x00FF;

    pub fn new() -> VariantDict {
        VariantDict {
            inner: HashMap::new(),
        }
    }

    #[inline]
    pub fn clear(&mut self) {
        self.inner.clear();
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn get<K: AsRef<str>>(&self, key: K) -> Option<&DictObject> {
        self.inner.get(key.as_ref())
    }

    pub fn set<K: Into<String>>(&mut self, key: K, value: DictObject) {
        self.inner.insert(key.into(), value);
    }

    pub fn set_u32<K: Into<String>>(&mut self, key: K, value: u32) {
        self.set(key, DictObject::UInt32(value));
    }

    pub fn set_u64<K: Into<String>>(&mut self, key: K, value: u64) {
        self.set(key, DictObject::UInt64(value));
    }

    pub fn set_i32<K: Into<String>>(&mut self, key: K, value: i32) {
        self.set(key, DictObject::Int32(value));
    }

    pub fn set_i64<K: Into<String>>(&mut self, key: K, value: i64) {
        self.set(key, DictObject::Int64(value));
    }

    pub fn set_string<K: Into<String>, V: Into<String>>(&mut self, key: K, value: V) {
        self.set(key, DictObject::String(value.into()));
    }

    pub fn set_arr<K: Into<String>, V: Into<Vec<u8>>>(&mut self, key: K, value: V) {
        self.set(key, DictObject::ByteArray(value.into()));
    }

    pub fn set_bool<K: Into<String>>(&mut self, key: K, value: bool) {
        self.set(key, DictObject::Bool(value));
    }

    pub fn get_u32<K: AsRef<str>>(&self, key: K) -> Option<u32> {
        if let Some(DictObject::UInt32(value)) = self.get(key) {
            Some(*value)
        } else {
            None
        }
    }

    pub fn get_u64<K: AsRef<str>>(&self, key: K) -> Option<u64> {
        if let Some(DictObject::UInt64(value)) = self.get(key) {
            Some(*value)
        } else {
            None
        }
    }

    pub fn get_i32<K: AsRef<str>>(&self, key: K) -> Option<i32> {
        if let Some(DictObject::Int32(value)) = self.get(key) {
            Some(*value)
        } else {
            None
        }
    }

    pub fn get_i64<K: AsRef<str>>(&self, key: K) -> Option<i64> {
        if let Some(DictObject::Int64(value)) = self.get(key) {
            Some(*value)
        } else {
            None
        }
    }

    pub fn get_bool<K: AsRef<str>>(&self, key: K) -> Option<bool> {
        if let Some(DictObject::Bool(value)) = self.get(key) {
            Some(*value)
        } else {
            None
        }
    }

    pub fn get_str<'s, K: AsRef<str>>(&'s self, key: K) -> Option<&'s str> {
        if let Some(DictObject::String(ref value)) = self.get(key) {
            Some(value)
        } else {
            None
        }
    }

    pub fn get_arr<'b, K: AsRef<str>>(&'b self, key: K) -> Option<&'b [u8]> {
        if let Some(DictObject::ByteArray(ref value)) = self.get(key) {
            Some(value)
        } else {
            None
        }
    }

    pub fn serialize<W: std::io::Write>(source: &VariantDict, mut out: W) -> Result<(), Error> {
        out.write_all(&memutil::u16_to_bytes(Self::VD_VERSION)).map_err(|e| Error::IO(e))?;

        for (key, value) in source.inner.iter() {
            // write out the type byte:
            out.write_all(&[VdType::type_of(value).to_int()]).map_err(|e| Error::IO(e))?;

            let name = key.as_bytes();
            out.write_all(&memutil::i32_to_bytes(name.len() as i32)).map_err(|e| Error::IO(e))?;
            out.write_all(name).map_err(|e| Error::IO(e))?;

            match value {
                &DictObject::UInt32(v) => {
                    out.write_all(&memutil::i32_to_bytes(4)).map_err(|e| Error::IO(e))?;
                    out.write_all(&memutil::u32_to_bytes(v)).map_err(|e| Error::IO(e))?;
                },

                &DictObject::UInt64(v) => {
                    out.write_all(&memutil::i32_to_bytes(8)).map_err(|e| Error::IO(e))?;
                    out.write_all(&memutil::u64_to_bytes(v)).map_err(|e| Error::IO(e))?;
                },

                &DictObject::Int32(v) => {
                    out.write_all(&memutil::i32_to_bytes(4)).map_err(|e| Error::IO(e))?;
                    out.write_all(&memutil::i32_to_bytes(v)).map_err(|e| Error::IO(e))?;
                },

                &DictObject::Int64(v) => {
                    out.write_all(&memutil::i32_to_bytes(8)).map_err(|e| Error::IO(e))?;
                    out.write_all(&memutil::i64_to_bytes(v)).map_err(|e| Error::IO(e))?;
                },

                &DictObject::String(ref v) => {
                    let bytes = v.as_bytes();
                    out.write_all(&memutil::i32_to_bytes(bytes.len() as i32)).map_err(|e| Error::IO(e))?;
                    out.write_all(bytes).map_err(|e| Error::IO(e))?;
                },

                &DictObject::ByteArray(ref v) => {
                    out.write_all(&memutil::i32_to_bytes(v.len() as i32)).map_err(|e| Error::IO(e))?;
                    out.write_all(&v).map_err(|e| Error::IO(e))?;
                },

                &DictObject::Bool(v) => {
                    out.write_all(&memutil::i32_to_bytes(1)).map_err(|e| Error::IO(e))?;
                    if v {
                        out.write_all(&[1]).map_err(|e| Error::IO(e))?;
                    } else {
                        out.write_all(&[0]).map_err(|e| Error::IO(e))?;
                    }
                },

                &DictObject::None => {
                    panic!("Dictionary object type was None.");
                },
            }
        }

        Ok(())
    }

    pub fn deserialize<R: std::io::Read>(dest: &mut VariantDict, mut data: R) -> Result<(), Error> {
        let version = ioutil::io_read_u16(&mut data)?;
        if (version & Self::VDM_CRITICAL) > (Self::VD_VERSION & Self::VDM_CRITICAL) {
            return Err(Error::BadFormat("Unsupported VariantDictionary version."));
        }

        let mut buffer: Vec<u8> = Vec::new();

        loop {
            let itype = ioutil::io_read_u8(&mut data)?;
            let vdtype = VdType::from_int(itype).ok_or(Error::BadFormat("File corrupted."))?;

            let len_name = ioutil::io_read_i32(&mut data)?;
            if len_name < 0 {
                return Err(Error::BadFormat("Name length less than 0."));
            }
            let name = ioutil::io_read_string(&mut data, len_name as usize)?;

            let len_value = ioutil::io_read_i32(&mut data)?;
            if len_value < 0 {
                return Err(Error::BadFormat("Value length less than 0."));
            }

            buffer.resize(len_value as usize, 0);
            data.read_exact(&mut buffer).map_err(|e| Error::IO(e))?;

            match vdtype {
                VdType::UInt32 => {
                    if buffer.len() != 4 {
                        return Err(Error::BadFormat("Bad u32 size."));
                    }
                    dest.set_u32(name, memutil::bytes_to_u32(&buffer));
                },

                VdType::UInt64 => {
                    if buffer.len() != 8 {
                        return Err(Error::BadFormat("Bad u64 size."));
                    }
                    dest.set_u64(name, memutil::bytes_to_u64(&buffer));
                },

                VdType::Bool => {
                    if buffer.len() != 1 {
                        return Err(Error::BadFormat("Bad bool size."));
                    }
                    dest.set_bool(name, buffer[0] != 0);
                },

                VdType::Int32 => {
                    if buffer.len() != 4 {
                        return Err(Error::BadFormat("Bad i32 size."));
                    }
                    dest.set_i32(name, memutil::bytes_to_i32(&buffer));
                },

                VdType::Int64 => {
                    if buffer.len() != 8 {
                        return Err(Error::BadFormat("Bad i64 size."));
                    }
                    dest.set_i64(name, memutil::bytes_to_i64(&buffer));
                },

                VdType::String => {
                    if let Ok(s) = String::from_utf8(buffer.clone()) {
                        dest.set_string(name, s);
                    } else {
                        return Err(Error::BadFormat("Invalid UTF8 String."));
                    }
                },

                VdType::ByteArray => {
                    dest.set_arr(name, buffer.clone());
                },

                VdType::None => {
                    return Err(Error::BadFormat("Unknown VariantDictionary type."));
                }
            }
        }

        Ok(())
    }
}
