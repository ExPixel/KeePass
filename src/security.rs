pub struct XorredBuffer {
    /// Contains data with a xor pad applied followed by the xor pad itself.
    /// The length of the data is the same as the length of the xor pad.
    data: Vec<u8>,
}

impl XorredBuffer {
    pub fn new(data: &[u8], xor_pad: &[u8]) -> XorredBuffer {
        assert!(data.len() == xor_pad.len(), "The length of the data must be the same length as the xor pad.");

        let mut v = Vec::new();
        (&mut v[0..data.len()]).copy_from_slice(data);
        (&mut v[data.len()..]).copy_from_slice(xor_pad);

        XorredBuffer {
            data: v,
        }
    }

    pub fn wrap(v: Vec<u8>) -> XorredBuffer {
        assert!(v.len() % 2 == 0, "The length of the data must be a multiple of 2.");
        XorredBuffer {
            data: v,
        }
    }

    /// Returns the length of the data contained in the XorredBuffer.
    #[inline]
    pub fn len(&self) -> usize {
        self.data.len() / 2
    }

    /// Places a copy of the plaintext into the destination slice.
    pub fn plaintext(&self, dest: &mut [u8]) {
        let data = &self.data[0..self.len()];
        let xor_pad = &self.data[self.len()..];

        assert!(data.len() == xor_pad.len());
        assert!(dest.len() == self.len(), "Destination buffer length must be the same as the data's length.");

        for idx in 0..data.len() {
            // @PERFORMANCE For some reason, rustc can vectorize this but not dest[idx] = data[idx] ^ xor_pad[idx]
            let d = data[idx];
            let x = xor_pad[idx];
            dest[idx] = d ^ x;
        }
    }

    /// **Appends** a copy of the plaintext into the destination vector.
    pub fn plaintext_vec(&self, dest: &mut Vec<u8>) {
        let offset = dest.len();
        dest.resize(offset + self.len(), 0);
        self.plaintext(&mut dest[offset..]);
    }
}

impl Drop for XorredBuffer {
    fn drop(&mut self) {
        crate::memutil::zero_vec(&mut self.data);
    }
}

/// A string that has its memory zeroed when it is dropped.
/// #TODO In KeePass's implementation the string is stored encrypted in memory.
///       I'm not sure how useful that is since it's constantly being unencrypted anyway
///       so I'll leave the implementation like this for now.
#[derive(Clone, PartialEq, Eq)]
pub struct ProtectedString {
    inner: String,
}

impl ProtectedString {
    pub fn wrap(value: String) -> ProtectedString {
        ProtectedString {
            inner: value
        }
    }

    pub fn get(this: &ProtectedString) -> &String {
        &this.inner
    }

    fn get_mut(this: &mut ProtectedString) -> &mut String {
        &mut this.inner
    }
}

impl Drop for ProtectedString {
    fn drop(&mut self) {
        let len = ProtectedString::get_mut(self).len();
        unsafe {
            crate::memutil::ptr_write_bytes_volatile(ProtectedString::get_mut(self).as_mut_str().as_bytes_mut().as_mut_ptr(), 0, len);
        }
    }
}

impl std::ops::Deref for ProtectedString {
    type Target = str;

    fn deref(&self) -> &str {
        &self.inner
    }
}

/// A vector of bytes that has its memory zeroed when it is dropped.
/// #TODO In KeePass's implementation the bytes are stored encrypted in memory.
///       I'm not sure how useful that is since it's constantly being unencrypted anyway
///       so I'll leave the implementation like this for now.
#[derive(Clone, PartialEq, Eq)]
pub struct ProtectedBinary {
    inner: Vec<u8>,
}

impl ProtectedBinary {
    pub fn empty() -> ProtectedBinary {
        Self::wrap(Vec::with_capacity(0))
    }

    pub fn new(len: usize) -> ProtectedBinary {
        let mut v = Vec::new();
        v.resize(len, 0);
        Self::wrap(v)
    }

    pub fn copy_slice(src: &[u8]) -> ProtectedBinary {
        let mut v = Vec::with_capacity(src.len());
        for b in src.iter() {
            v.push(*b);
        }
        Self::wrap(v)
    }

    pub fn wrap(value: Vec<u8>) -> ProtectedBinary {
        ProtectedBinary {
            inner: value
        }
    }

    pub fn get(this: &ProtectedBinary) -> &[u8] {
        &this.inner
    }

    fn get_mut(this: &mut ProtectedBinary) -> &mut Vec<u8> {
        &mut this.inner
    }

    /// Copies some data into a protected binary.
    pub fn copy_into(this: &mut ProtectedBinary, offset: usize, src: &[u8]) {
        assert!(offset < this.len(), "offset is out of bounds");

        let len = if src.len() < (this.len() - offset) {
            src.len()
        } else {
            this.len() - offset
        };

        for idx in 0..len {
            unsafe {
                *(Self::get_mut(this).get_unchecked_mut(idx + offset)) = *src.get_unchecked(idx);
            }
        }
    }
}

impl Drop for ProtectedBinary {
    fn drop(&mut self) {
        let len = ProtectedBinary::get_mut(self).len();
        unsafe {
            crate::memutil::ptr_write_bytes_volatile(ProtectedBinary::get_mut(self).as_mut_ptr(), 0, len);
        }
    }
}

impl Default for ProtectedBinary {
    fn default() -> ProtectedBinary {
        ProtectedBinary {
            inner: Default::default(),
        }
    }
}

impl std::ops::Deref for ProtectedBinary {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        &self.inner
    }
}

impl std::convert::AsRef<[u8]> for ProtectedBinary {
    fn as_ref(&self) -> &[u8] {
        &self.inner
    }
}
