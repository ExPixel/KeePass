use crate::error::Error;
use crate::memutil;

/// A reader that will also write all read bytes into a writer.
pub struct ReadInto<R: std::io::Read, W: std::io::Write> {
    read: R,
    write: W,
}

impl<R: std::io::Read, W: std::io::Write> ReadInto<R, W> {
    pub fn new(read: R, write: W) -> ReadInto<R, W> {
        ReadInto {
            read: read,
            write: write,
        }
    }

    pub fn into_inner(self) -> (R, W) {
        (self.read, self.write)
    }

    pub fn get_write(&self) -> &W {
        &self.write
    }

    pub fn get_read(&self) -> &R {
        &self.read
    }
}

impl<R: std::io::Read, W: std::io::Write> std::io::Read for ReadInto<R, W> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self.read.read(buf) {
            Ok(bytes_read) => {
                self.write.write_all(&buf[0..bytes_read])?;
                Ok(bytes_read)
            },

            Err(err) => {
                Err(err)
            }
        }
    }
}

/// A reader that stores all bytes read from its internal reader.
/// This version only requires a mutable reference to another reader.
pub struct StoredReadRef<'r, R: std::io::Read> {
    inner: &'r mut R,
    store: Vec<u8>,
}

impl<'r, R: std::io::Read> StoredReadRef<'r, R> {
    pub fn new(read: &'r mut R) -> StoredReadRef<'r, R> {
        StoredReadRef {
            inner: read,
            store: Vec::new(),
        }
    }

    pub fn data(self) -> Vec<u8> {
        self.store
    }
}

impl<'r, R: std::io::Read> std::io::Read for StoredReadRef<'r, R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self.inner.read(buf) {
            Ok(bytes_read) => {
                self.store.extend_from_slice(&buf[0..bytes_read]);
                Ok(bytes_read)
            },

            Err(err) => {
                Err(err)
            }
        }
    }
}

/// A reader that stores all bytes read from its internal reader.
pub struct StoredRead<R: std::io::Read> {
    inner: R,
    store: Vec<u8>,
}

impl<R: std::io::Read> StoredRead<R> {
    pub fn new(read: R) -> StoredRead<R> {
        StoredRead {
            inner: read,
            store: Vec::new(),
        }
    }

    pub fn into_inner(self) -> (R, Vec<u8>) {
        (self.inner, self.store)
    }
}

impl<R: std::io::Read> std::io::Read for StoredRead<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self.inner.read(buf) {
            Ok(bytes_read) => {
                self.store.extend_from_slice(&buf[0..bytes_read]);
                Ok(bytes_read)
            },

            Err(err) => {
                Err(err)
            }
        }
    }
}

pub fn io_read_u8<R: std::io::Read>(input: &mut R) -> Result<u8, Error> {
    let mut dest = [0u8; 1];
    input.read_exact(&mut dest).map_err(|e| Error::IO(e))?;
    Ok(dest[0])
}

/// Reads 2 bytes in little-endian order from a reader and converts them into a u16.
#[inline]
pub fn io_read_u16<R: std::io::Read>(input: &mut R) -> Result<u16, Error> {
    let mut dest = [0u8; 2];
    input.read_exact(&mut dest).map_err(|e| Error::IO(e))?;
    Ok(memutil::bytes_to_u16(&dest))
}

/// Reads 4 bytes in little-endian order from a reader and converts them into a u32.
#[inline]
pub fn io_read_u32<R: std::io::Read>(input: &mut R) -> Result<u32, Error> {
    let mut dest = [0u8; 4];
    input.read_exact(&mut dest).map_err(|e| Error::IO(e))?;
    Ok(memutil::bytes_to_u32(&dest))
}

/// Reads 8 bytes in little-endian order from a reader and converts them into a u32.
pub fn io_read_u64<R: std::io::Read>(input: &mut R) -> Result<u64, Error> {
    let mut dest = [0u8; 8];
    input.read_exact(&mut dest).map_err(|e| Error::IO(e))?;
    Ok(memutil::bytes_to_u64(&dest))
}

pub fn io_read_i8<R: std::io::Read>(input: &mut R) -> Result<i8, Error> {
    let mut dest = [0u8; 1];
    input.read_exact(&mut dest).map_err(|e| Error::IO(e))?;
    Ok(dest[0] as i8)
}

/// Reads 2 bytes in little-endian order from a reader and converts them into an i16.
#[inline]
pub fn io_read_i16<R: std::io::Read>(input: &mut R) -> Result<i16, Error> {
    let mut dest = [0u8; 2];
    input.read_exact(&mut dest).map_err(|e| Error::IO(e))?;
    Ok(memutil::bytes_to_i16(&dest))
}

/// Reads 4 bytes in little-endian order from a reader and converts them into an i32.
#[inline]
pub fn io_read_i32<R: std::io::Read>(input: &mut R) -> Result<i32, Error> {
    let mut dest = [0u8; 4];
    input.read_exact(&mut dest).map_err(|e| Error::IO(e))?;
    Ok(memutil::bytes_to_i32(&dest))
}

/// Reads 8 bytes in little-endian order from a reader and converts them into an i64.
pub fn io_read_i64<R: std::io::Read>(input: &mut R) -> Result<i64, Error> {
    let mut dest = [0u8; 8];
    input.read_exact(&mut dest).map_err(|e| Error::IO(e))?;
    Ok(memutil::bytes_to_i64(&dest))
}

/// Reads a string of a given size from a reader.
pub fn io_read_string<R: std::io::Read>(input: &mut R, len: usize) -> Result<String, Error> {
    let mut bytes = Vec::with_capacity(len);
    bytes.resize(len, 0);
    input.read_exact(&mut bytes).map_err(|e| Error::IO(e))?;

    // @TODO remove this possible panic
    let string = String::from_utf8(bytes).expect("invalid string");

    Ok(string)
}

