use sha2::{Sha256, Digest as _};
use crate::error::Error;

pub struct HashedBlockRead<'r> {
    inner: &'r mut std::io::Read,
    block_index: u32,
    /// position in the buffer
    buf_offset: usize,
    buffer: Vec<u8>,
    done: bool,
    verify: bool,
}

impl<'r> HashedBlockRead<'r> {
    pub fn new(inner: &'r mut std::io::Read, verify: bool) -> HashedBlockRead<'r> {
        HashedBlockRead {
            inner: inner,
            block_index: 0,
            buf_offset: 0,
            buffer: Vec::new(),
            done: false,
            verify: verify,
        }
    }

    fn read_hashed_block(&mut self) -> std::io::Result<bool> {
        debug_assert!(!self.done, "Cannot read another hased block after the end of the inner stream has been reached.");

        let mut indexbytes = [0u8; 4];
        self.inner.read_exact(&mut indexbytes)?;
        let expected_block_index = {
            let iindex = crate::memutil::bytes_to_i32(&indexbytes);
            if iindex < 0 {
                return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, Error::BadFormat("Invalid hashed block stream block index.")));
            } else {
                iindex as u32
            }
        };

        if expected_block_index != self.block_index {
                return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, Error::BadFormat("Unexpected hashed block stream block index.")));
        } else {
            self.block_index += 1;
        }

        let mut expected_hash = [0u8; 32];
        self.inner.read_exact(&mut expected_hash)?;

        let mut lenbytes = [0u8; 4];
        self.inner.read_exact(&mut lenbytes)?;
        let len = {
            let ilen = crate::memutil::bytes_to_i32(&lenbytes);
            if ilen < 0 {
                return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, Error::BadFormat("Invalid hashed block stream block size.")));
            } else {
                ilen as usize
            }
        };

        if len == 0 {
            for b in expected_hash.iter() {
                if *b != 0 {
                    return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, Error::BadFormat("Invalid hashed block stream end.")));
                }
            }
            self.done = true;
            return Ok(false);
        }

        self.buffer.resize(len, 0);
        self.inner.read_exact(&mut self.buffer)?;

        if self.verify {
            let mut hasher = Sha256::new();
            hasher.input(&self.buffer);
            if &hasher.result()[0..] != expected_hash {
                return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, Error::BadFormat("Invalid hashed block stream block hash.")));
            }
        }

        self.buf_offset = 0;
        return Ok(true);
    }
}

impl<'r> std::io::Read for HashedBlockRead<'r> {
    fn read(&mut self, dest: &mut [u8]) -> std::io::Result<usize> {
        if self.done {
            Ok(0)
        } else {
            let mut read = 0;

            while read < dest.len() {
                if self.buf_offset < self.buffer.len() {
                    let count = std::cmp::min(dest.len(), self.buffer.len() - self.buf_offset);
                    (&mut dest[read..(read + count)]).copy_from_slice(&self.buffer[self.buf_offset..(self.buf_offset + count)]);
                    self.buf_offset += count;
                    read += count;
                } else {
                    if !(self.read_hashed_block()?) {
                        break
                    }
                }
            }

            Ok(read)
        }
    }
}
