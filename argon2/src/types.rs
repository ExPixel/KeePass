use super::sys;

/// Error type returned by all Rust wrappers of Argon2 functions.
#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    /// This error is returned whenever a bad parameter is passed in but doesn't make it past the
    /// wrapper layer. e.g. a parameter that cannot be converted to the type required by the argon2
    /// C library.
    BadParam(&'static str),

    /// An error returned from the argon2 C library in the form of an error code.
    Code(ErrorCode),

    /// An error occurred an argon2 but it has no Rust wrapper.
    /// These are bugs in the library itself.
    Unknown,
}

impl Error {
    pub(crate) fn check_code(code: sys::Argon2_ErrorCodes) -> Result<(), Error> {
        if code == 0 {
            Ok(())
        } else {
            if let Some(err_code) = ErrorCode::from_c(code as sys::Argon2_ErrorCodes) {
                Err(Error::Code(err_code))
            } else {
                Err(Error::Unknown)
            }
        }
    }
}

/// Error code returned by failed Argon2 C functions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum ErrorCode {
    OutputPtrNull = sys::Argon2_ErrorCodes_ARGON2_OUTPUT_PTR_NULL,
    OutputTooShort = sys::Argon2_ErrorCodes_ARGON2_OUTPUT_TOO_SHORT,
    OutputTooLong = sys::Argon2_ErrorCodes_ARGON2_OUTPUT_TOO_LONG,
    PwdTooShort = sys::Argon2_ErrorCodes_ARGON2_PWD_TOO_SHORT,
    PwdTooLong = sys::Argon2_ErrorCodes_ARGON2_PWD_TOO_LONG,
    SaltTooShort = sys::Argon2_ErrorCodes_ARGON2_SALT_TOO_SHORT,
    SaltTooLong = sys::Argon2_ErrorCodes_ARGON2_SALT_TOO_LONG,
    AdTooShort = sys::Argon2_ErrorCodes_ARGON2_AD_TOO_SHORT,
    AdTooLong = sys::Argon2_ErrorCodes_ARGON2_AD_TOO_LONG,
    SecretTooShort = sys::Argon2_ErrorCodes_ARGON2_SECRET_TOO_SHORT,
    SecretTooLong = sys::Argon2_ErrorCodes_ARGON2_SECRET_TOO_LONG,
    TimeTooSmall = sys::Argon2_ErrorCodes_ARGON2_TIME_TOO_SMALL,
    TimeTooLarge = sys::Argon2_ErrorCodes_ARGON2_TIME_TOO_LARGE,
    MemoryTooLittle = sys::Argon2_ErrorCodes_ARGON2_MEMORY_TOO_LITTLE,
    MemoryTooMuch = sys::Argon2_ErrorCodes_ARGON2_MEMORY_TOO_MUCH,
    LanesTooFew = sys::Argon2_ErrorCodes_ARGON2_LANES_TOO_FEW,
    LanesTooMany = sys::Argon2_ErrorCodes_ARGON2_LANES_TOO_MANY,
    PwdPtrMismatch = sys::Argon2_ErrorCodes_ARGON2_PWD_PTR_MISMATCH,
    SaltPtrMismatch = sys::Argon2_ErrorCodes_ARGON2_SALT_PTR_MISMATCH,
    SecretPtrMismatch = sys::Argon2_ErrorCodes_ARGON2_SECRET_PTR_MISMATCH,
    AdPtrMismatch = sys::Argon2_ErrorCodes_ARGON2_AD_PTR_MISMATCH,
    MemoryAllocationError = sys::Argon2_ErrorCodes_ARGON2_MEMORY_ALLOCATION_ERROR,
    FreeMemoryCbkNull = sys::Argon2_ErrorCodes_ARGON2_FREE_MEMORY_CBK_NULL,
    AllocateMemoryCbkNull = sys::Argon2_ErrorCodes_ARGON2_ALLOCATE_MEMORY_CBK_NULL,
    IncorrectParameter = sys::Argon2_ErrorCodes_ARGON2_INCORRECT_PARAMETER,
    IncorrectType = sys::Argon2_ErrorCodes_ARGON2_INCORRECT_TYPE,
    OutPtrMismatch = sys::Argon2_ErrorCodes_ARGON2_OUT_PTR_MISMATCH,
    ThreadsTooFew = sys::Argon2_ErrorCodes_ARGON2_THREADS_TOO_FEW,
    ThreadsTooMany = sys::Argon2_ErrorCodes_ARGON2_THREADS_TOO_MANY,
    MissingArgs = sys::Argon2_ErrorCodes_ARGON2_MISSING_ARGS,
    EncodingFail = sys::Argon2_ErrorCodes_ARGON2_ENCODING_FAIL,
    DecodingFail = sys::Argon2_ErrorCodes_ARGON2_DECODING_FAIL,
    ThreadFail = sys::Argon2_ErrorCodes_ARGON2_THREAD_FAIL,
    DecodingLengthFail = sys::Argon2_ErrorCodes_ARGON2_DECODING_LENGTH_FAIL,
    VerifyMismatch = sys::Argon2_ErrorCodes_ARGON2_VERIFY_MISMATCH,
}

impl ErrorCode {
    /// Get the associated message for this error code.
    pub fn message(self) -> Option<&'static str> {
        super::error_message(self)
    }

    /// Converts an Argon2 error code into a Rust representation.
    fn from_c(c_error_code: sys::Argon2_ErrorCodes) -> Option<ErrorCode> {
        match c_error_code {
            sys::Argon2_ErrorCodes_ARGON2_OUTPUT_PTR_NULL => Some(ErrorCode::OutputPtrNull),
            sys::Argon2_ErrorCodes_ARGON2_OUTPUT_TOO_SHORT => Some(ErrorCode::OutputTooShort),
            sys::Argon2_ErrorCodes_ARGON2_OUTPUT_TOO_LONG => Some(ErrorCode::OutputTooLong),
            sys::Argon2_ErrorCodes_ARGON2_PWD_TOO_SHORT => Some(ErrorCode::PwdTooShort),
            sys::Argon2_ErrorCodes_ARGON2_PWD_TOO_LONG => Some(ErrorCode::PwdTooLong),
            sys::Argon2_ErrorCodes_ARGON2_SALT_TOO_SHORT => Some(ErrorCode::SaltTooShort),
            sys::Argon2_ErrorCodes_ARGON2_SALT_TOO_LONG => Some(ErrorCode::SaltTooLong),
            sys::Argon2_ErrorCodes_ARGON2_AD_TOO_SHORT => Some(ErrorCode::AdTooShort),
            sys::Argon2_ErrorCodes_ARGON2_AD_TOO_LONG => Some(ErrorCode::AdTooLong),
            sys::Argon2_ErrorCodes_ARGON2_SECRET_TOO_SHORT => Some(ErrorCode::SecretTooShort),
            sys::Argon2_ErrorCodes_ARGON2_SECRET_TOO_LONG => Some(ErrorCode::SecretTooLong),
            sys::Argon2_ErrorCodes_ARGON2_TIME_TOO_SMALL => Some(ErrorCode::TimeTooSmall),
            sys::Argon2_ErrorCodes_ARGON2_TIME_TOO_LARGE => Some(ErrorCode::TimeTooLarge),
            sys::Argon2_ErrorCodes_ARGON2_MEMORY_TOO_LITTLE => Some(ErrorCode::MemoryTooLittle),
            sys::Argon2_ErrorCodes_ARGON2_MEMORY_TOO_MUCH => Some(ErrorCode::MemoryTooMuch),
            sys::Argon2_ErrorCodes_ARGON2_LANES_TOO_FEW => Some(ErrorCode::LanesTooFew),
            sys::Argon2_ErrorCodes_ARGON2_LANES_TOO_MANY => Some(ErrorCode::LanesTooMany),
            sys::Argon2_ErrorCodes_ARGON2_PWD_PTR_MISMATCH => Some(ErrorCode::PwdPtrMismatch),
            sys::Argon2_ErrorCodes_ARGON2_SALT_PTR_MISMATCH => Some(ErrorCode::SaltPtrMismatch),
            sys::Argon2_ErrorCodes_ARGON2_SECRET_PTR_MISMATCH => Some(ErrorCode::SecretPtrMismatch),
            sys::Argon2_ErrorCodes_ARGON2_AD_PTR_MISMATCH => Some(ErrorCode::AdPtrMismatch),
            sys::Argon2_ErrorCodes_ARGON2_MEMORY_ALLOCATION_ERROR => Some(ErrorCode::MemoryAllocationError),
            sys::Argon2_ErrorCodes_ARGON2_FREE_MEMORY_CBK_NULL => Some(ErrorCode::FreeMemoryCbkNull),
            sys::Argon2_ErrorCodes_ARGON2_ALLOCATE_MEMORY_CBK_NULL => Some(ErrorCode::AllocateMemoryCbkNull),
            sys::Argon2_ErrorCodes_ARGON2_INCORRECT_PARAMETER => Some(ErrorCode::IncorrectParameter),
            sys::Argon2_ErrorCodes_ARGON2_INCORRECT_TYPE => Some(ErrorCode::IncorrectType),
            sys::Argon2_ErrorCodes_ARGON2_OUT_PTR_MISMATCH => Some(ErrorCode::OutPtrMismatch),
            sys::Argon2_ErrorCodes_ARGON2_THREADS_TOO_FEW => Some(ErrorCode::ThreadsTooFew),
            sys::Argon2_ErrorCodes_ARGON2_THREADS_TOO_MANY => Some(ErrorCode::ThreadsTooMany),
            sys::Argon2_ErrorCodes_ARGON2_MISSING_ARGS => Some(ErrorCode::MissingArgs),
            sys::Argon2_ErrorCodes_ARGON2_ENCODING_FAIL => Some(ErrorCode::EncodingFail),
            sys::Argon2_ErrorCodes_ARGON2_DECODING_FAIL => Some(ErrorCode::DecodingFail),
            sys::Argon2_ErrorCodes_ARGON2_THREAD_FAIL => Some(ErrorCode::ThreadFail),
            sys::Argon2_ErrorCodes_ARGON2_DECODING_LENGTH_FAIL => Some(ErrorCode::DecodingLengthFail),
            sys::Argon2_ErrorCodes_ARGON2_VERIFY_MISMATCH => Some(ErrorCode::VerifyMismatch),

            _ => None,
        }
    }

    /// Converts a Rust representation of an Argon2 error code into the C error code.
    pub(crate) fn to_c(self: ErrorCode) -> sys::Argon2_ErrorCodes {
        match self {
            ErrorCode::OutputPtrNull => sys::Argon2_ErrorCodes_ARGON2_OUTPUT_PTR_NULL,
            ErrorCode::OutputTooShort => sys::Argon2_ErrorCodes_ARGON2_OUTPUT_TOO_SHORT,
            ErrorCode::OutputTooLong => sys::Argon2_ErrorCodes_ARGON2_OUTPUT_TOO_LONG,
            ErrorCode::PwdTooShort => sys::Argon2_ErrorCodes_ARGON2_PWD_TOO_SHORT,
            ErrorCode::PwdTooLong => sys::Argon2_ErrorCodes_ARGON2_PWD_TOO_LONG,
            ErrorCode::SaltTooShort => sys::Argon2_ErrorCodes_ARGON2_SALT_TOO_SHORT,
            ErrorCode::SaltTooLong => sys::Argon2_ErrorCodes_ARGON2_SALT_TOO_LONG,
            ErrorCode::AdTooShort => sys::Argon2_ErrorCodes_ARGON2_AD_TOO_SHORT,
            ErrorCode::AdTooLong => sys::Argon2_ErrorCodes_ARGON2_AD_TOO_LONG,
            ErrorCode::SecretTooShort => sys::Argon2_ErrorCodes_ARGON2_SECRET_TOO_SHORT,
            ErrorCode::SecretTooLong => sys::Argon2_ErrorCodes_ARGON2_SECRET_TOO_LONG,
            ErrorCode::TimeTooSmall => sys::Argon2_ErrorCodes_ARGON2_TIME_TOO_SMALL,
            ErrorCode::TimeTooLarge => sys::Argon2_ErrorCodes_ARGON2_TIME_TOO_LARGE,
            ErrorCode::MemoryTooLittle => sys::Argon2_ErrorCodes_ARGON2_MEMORY_TOO_LITTLE,
            ErrorCode::MemoryTooMuch => sys::Argon2_ErrorCodes_ARGON2_MEMORY_TOO_MUCH,
            ErrorCode::LanesTooFew => sys::Argon2_ErrorCodes_ARGON2_LANES_TOO_FEW,
            ErrorCode::LanesTooMany => sys::Argon2_ErrorCodes_ARGON2_LANES_TOO_MANY,
            ErrorCode::PwdPtrMismatch => sys::Argon2_ErrorCodes_ARGON2_PWD_PTR_MISMATCH,
            ErrorCode::SaltPtrMismatch => sys::Argon2_ErrorCodes_ARGON2_SALT_PTR_MISMATCH,
            ErrorCode::SecretPtrMismatch => sys::Argon2_ErrorCodes_ARGON2_SECRET_PTR_MISMATCH,
            ErrorCode::AdPtrMismatch => sys::Argon2_ErrorCodes_ARGON2_AD_PTR_MISMATCH,
            ErrorCode::MemoryAllocationError => sys::Argon2_ErrorCodes_ARGON2_MEMORY_ALLOCATION_ERROR,
            ErrorCode::FreeMemoryCbkNull => sys::Argon2_ErrorCodes_ARGON2_FREE_MEMORY_CBK_NULL,
            ErrorCode::AllocateMemoryCbkNull => sys::Argon2_ErrorCodes_ARGON2_ALLOCATE_MEMORY_CBK_NULL,
            ErrorCode::IncorrectParameter => sys::Argon2_ErrorCodes_ARGON2_INCORRECT_PARAMETER,
            ErrorCode::IncorrectType => sys::Argon2_ErrorCodes_ARGON2_INCORRECT_TYPE,
            ErrorCode::OutPtrMismatch => sys::Argon2_ErrorCodes_ARGON2_OUT_PTR_MISMATCH,
            ErrorCode::ThreadsTooFew => sys::Argon2_ErrorCodes_ARGON2_THREADS_TOO_FEW,
            ErrorCode::ThreadsTooMany => sys::Argon2_ErrorCodes_ARGON2_THREADS_TOO_MANY,
            ErrorCode::MissingArgs => sys::Argon2_ErrorCodes_ARGON2_MISSING_ARGS,
            ErrorCode::EncodingFail => sys::Argon2_ErrorCodes_ARGON2_ENCODING_FAIL,
            ErrorCode::DecodingFail => sys::Argon2_ErrorCodes_ARGON2_DECODING_FAIL,
            ErrorCode::ThreadFail => sys::Argon2_ErrorCodes_ARGON2_THREAD_FAIL,
            ErrorCode::DecodingLengthFail => sys::Argon2_ErrorCodes_ARGON2_DECODING_LENGTH_FAIL,
            ErrorCode::VerifyMismatch => sys::Argon2_ErrorCodes_ARGON2_VERIFY_MISMATCH,
        }
    }
}

/// Argon2 primitive type.
#[derive(Debug, Clone, Copy)]
pub enum Variant {
    D   = 0,
    I   = 1,
    ID  = 2,
}

impl Variant {
    /// Converts from the C Variant type to the Rust Variant Type.
    #[inline]
    #[allow(dead_code)]
    fn from_c(c_variant: sys::Argon2_type) -> Variant {
        match c_variant {
            sys::Argon2_type_Argon2_d   => Variant::D,
            sys::Argon2_type_Argon2_i   => Variant::I,
            sys::Argon2_type_Argon2_id  => Variant::ID,
            _ => panic!("Unimplemented version {}", c_variant),
        }
    }

    /// Converts from the Rust Variant type to the C Variant Type.
    #[inline]
    pub(crate) fn to_c(self) -> sys::Argon2_type {
        match self {
            Variant::D  => sys::Argon2_type_Argon2_d,
            Variant::I  => sys::Argon2_type_Argon2_i,
            Variant::ID => sys::Argon2_type_Argon2_id,
        }
    }
}

/// Version of the algorithm.
#[derive(Debug, Clone, Copy)]
pub enum Version {
    /// Argon2 Version 0x10
    Version10 = 0x10,

    /// Argon2 Version 0x13
    Version13 = 0x13,
}

impl Version {
    /// Converts the version to an integer.
    pub fn to_int(self) -> u32 {
        match self {
            Version::Version10 => 0x10,
            Version::Version13 => 0x13,
        }
    }

    /// Converts an integer to a Version if possible.
    pub fn from_int(n: u32) -> Option<Version> {
        match n {
            0x10 => Some(Version::Version10),
            0x13 => Some(Version::Version13),
            _ => None,
        }
    }

    /// Converts the C version type to the Rust version type.
    #[inline]
    #[allow(dead_code)]
    pub(crate) fn from_c(c_version: sys::Argon2_version) -> Version {
        match c_version {
            sys::Argon2_version_ARGON2_VERSION_10 => Version::Version10,
            sys::Argon2_version_ARGON2_VERSION_13 => Version::Version13,
            _ => panic!("Unimplemented version 0x{:X}", c_version),
        }
    }

    /// Converts the Rust version type to the C version type.
    #[inline]
    pub(crate) fn to_c(self) -> sys::Argon2_version {
        match self {
            Version::Version10 => sys::Argon2_version_ARGON2_VERSION_10,
            Version::Version13 => sys::Argon2_version_ARGON2_VERSION_13,
        }
    }
}

impl Default for Version {
    /// Returns the latest version of the algorithm.
    fn default() -> Version {
        Version::Version13
    }
}

bitflags::bitflags! {
    /// Flags which control fields are securely wiped (zeroed).
    pub struct Flags: u32 {
        /// No wipe.
        const DEFAULT           = 0;
        /// Wipe the password field.
        const CLEAR_PASSWORD    = 1 << 0;
        /// Wipe the secret field.
        const CLEAR_SECRET      = 1 << 1;
    }
}

/// Structure to hold Argon2 inputs.
pub struct Context<'o, 'p, 'sa, 'se, 'ad> {
    /// Output array.
    pub out:    &'o mut [u8],
    /// Password array.
    pub pwd:    Option<&'p mut [u8]>,
    /// Salt array.
    pub salt:   Option<&'sa mut [u8]>,
    /// Secret array.
    pub secret: Option<&'se mut [u8]>,
    /// Associated data array.
    pub ad:     Option<&'ad mut [u8]>,

    /// Number of passes.
    pub t_cost: u32,
    /// Amount of memory requested (KB)
    pub m_cost: u32,
    /// Number of lanes.
    pub lanes:  u32,
    /// Maximum number of threads.
    pub threads:u32,

    /// Version number.
    pub version: Version,

    /// Array of bool options
    pub flags: Flags,
}

impl<'o, 'p, 'sa, 'se, 'ad> Context<'o, 'p, 'sa, 'se, 'ad> {
    /// Minimum number of lanes (degree of parallelism).
    pub const MIN_LANES: u32 = 1;
    /// Maximum number of lanes (degree of parallelism).
    pub const MAX_LANES: u32 = 0xFFFFFF;

    /// Number of synchronization points between lanes per pass.
    pub const SYNC_POINTS: u32 = 4;

    /// Minimum number of threads.
    pub const MIN_THREADS: u32 = 1;
    /// Maximum number of threads.
    pub const MAX_THREADS: u32 = 0xFFFFFF;

    /// Minimum digest size in bytes.
    pub const MIN_OUTLEN: u32 = 4;
    /// Maximum digest size in bytes.
    pub const MAX_OUTLEN: u32 = 0xFFFFFFFF;

    /// Minimum number of passes.
    pub const MIN_TIME: u32 = 1;
    /// Maximum number of passes.
    pub const MAX_TIME: u32 = 0xFFFFFFFF;

    /// Minimum password length in bytes.
    pub const MIN_PWD_LENGTH: u32 = 0;
    /// Maximum password length in bytes.
    pub const MAX_PWD_LENGTH: u32 = 0xFFFFFFFF;

    /// Minimum associated data length in bytes.
    pub const MIN_AD_LENGTH: u32 = 0;
    /// Maximum associated data length in bytes.
    pub const MAX_AD_LENGTH: u32 = 0xFFFFFFFF;

    /// Minimum salt length in bytes.
    pub const MIN_SALT_LENGTH: u32 = 8;
    /// Maximum salt length in bytes.
    pub const MAX_SALT_LENGTH: u32 = 0xFFFFFFFF;

    /// Minimum key length in bytes.
    pub const MIN_SECRET_LENGTH: u32 = 0;
    /// Maximum key length in bytes.
    pub const MAX_SECRET_LENGTH: u32 = 0xFFFFFFFF;

    pub(crate) fn try_to_c(&mut self) -> Result<sys::Argon2_Context, Error> {
        Ok(sys::Argon2_Context {
            out: self.out.as_mut_ptr(),
            outlen: try_conv("context.out.len", self.out.len())?,
            pwd: opt_slice_ptr_mut(&mut self.pwd),
            pwdlen: opt_slice_len_u32("context.pwd.len", &self.pwd)?,
            salt: opt_slice_ptr_mut(&mut self.salt),
            saltlen: opt_slice_len_u32("context.salt.len", &self.pwd)?,
            secret: opt_slice_ptr_mut(&mut self.secret),
            secretlen: opt_slice_len_u32("context.secret.len", &self.secret)?,
            ad: opt_slice_ptr_mut(&mut self.ad),
            adlen: opt_slice_len_u32("context.ad.len", &self.ad)?,
            t_cost: self.t_cost,
            m_cost: self.m_cost,
            lanes: self.lanes,
            threads: self.threads,
            version: self.version.to_c() as _,
            allocate_cbk: None,
            free_cbk: None,
            flags: self.flags.bits(),
        })
    }
}

/// Structure to hold Argon2 inputs. Unlike `Context`, this version owns all of the input values.
pub struct OwnedContext {
    /// Output array.
    pub out:    Vec<u8>,
    /// Password array.
    pub pwd:    Option<Vec<u8>>,
    /// Salt array.
    pub salt:   Option<Vec<u8>>,
    /// Secret array.
    pub secret: Option<Vec<u8>>,
    /// Associated data array.
    pub ad:     Option<Vec<u8>>,

    /// Number of passes.
    pub t_cost: u32,
    /// Amount of memory requested (KB)
    pub m_cost: u32,
    /// Number of lanes.
    pub lanes:  u32,
    /// Maximum number of threads.
    pub threads:u32,

    /// Version number.
    pub version: Version,

    /// Array of bool options
    pub flags: Flags,
}

impl OwnedContext {
    pub fn borrowed<'a>(&'a mut self) -> Context<'a, 'a, 'a, 'a, 'a> {
        Context {
            out: &mut self.out,
            pwd: self.pwd.as_mut().map(|v| &mut v[0..]),
            salt: self.salt.as_mut().map(|v| &mut v[0..]),
            secret: self.secret.as_mut().map(|v| &mut v[0..]),
            ad: self.ad.as_mut().map(|v| &mut v[0..]),
            t_cost: self.t_cost,
            m_cost: self.m_cost,
            lanes: self.lanes,
            threads: self.threads,
            version: self.version,
            flags: self.flags.clone(),
        }
    }

    pub(crate) fn try_to_c(&mut self) -> Result<sys::Argon2_Context, Error> {
        Ok(sys::Argon2_Context {
            out: self.out.as_mut_ptr(),
            outlen: try_conv("context.out.len", self.out.len())?,
            pwd: opt_slice_ptr_mut(&mut self.pwd),
            pwdlen: opt_slice_len_u32("context.pwd.len", &self.pwd)?,
            salt: opt_slice_ptr_mut(&mut self.salt),
            saltlen: opt_slice_len_u32("context.salt.len", &self.pwd)?,
            secret: opt_slice_ptr_mut(&mut self.secret),
            secretlen: opt_slice_len_u32("context.secret.len", &self.secret)?,
            ad: opt_slice_ptr_mut(&mut self.ad),
            adlen: opt_slice_len_u32("context.ad.len", &self.ad)?,
            t_cost: self.t_cost,
            m_cost: self.m_cost,
            lanes: self.lanes,
            threads: self.threads,
            version: self.version.to_c() as _,
            allocate_cbk: None,
            free_cbk: None,
            flags: self.flags.bits(),
        })
    }
}

impl<'o, 'p, 'sa, 'se, 'ad> std::convert::TryFrom<&mut Context<'o, 'p, 'sa, 'se, 'ad>> for sys::Argon2_Context {
    type Error = self::Error;

    fn try_from(context: &mut Context<'o, 'p, 'sa, 'se, 'ad>) -> Result<Self, Self::Error> {
        context.try_to_c()
    }
}

impl std::convert::TryFrom<&mut OwnedContext> for sys::Argon2_Context {
    type Error = self::Error;

    fn try_from(context: &mut OwnedContext) -> Result<Self, Self::Error> {
        context.try_to_c()
    }
}

/// Tries to convert between two types and returns a BadParam error on failure.
#[inline]
pub(crate) fn try_conv<T, U: std::convert::TryFrom<T>>(param: &'static str, input: T) -> Result<U, Error> {
    U::try_from(input).map_err(|_| Error::BadParam(param))
}

/// Gets the length of a slice contained an in option (0 if none).
#[inline]
pub(crate) fn opt_slice_len<T, S: AsRef<[T]>>(opt: &Option<S>) -> usize {
    opt.as_ref().map(|s| s.as_ref().len()).unwrap_or(0)
}

/// Gets the length of a slice contained in an option (0 if none) and tries to convert the size to
/// a u32, returning an error on failure.
#[inline]
pub(crate) fn opt_slice_len_u32<T, S: AsRef<[T]>>(param: &'static str, opt: &Option<S>) -> Result<u32, Error> {
    try_conv(param, opt.as_ref().map(|s| s.as_ref().len()).unwrap_or(0))
}

/// Converts an option containing a slice into a mutable pointer that is null if the option is
/// None.
#[inline]
pub(crate) fn opt_slice_ptr_mut<T, S: AsMut<[T]>>(opt: &mut Option<S>) -> *mut T {
    opt.as_mut()
        .map(|s| s.as_mut().as_mut_ptr())
        .unwrap_or(std::ptr::null_mut())
}

/// Converts an option containing a slice into a mutable pointer that is null if the option is
/// None.
#[inline]
pub(crate) fn opt_slice_ptr<T, S: AsRef<[T]>>(opt: &Option<S>) -> *const T {
    opt.as_ref()
        .map(|s| s.as_ref().as_ptr())
        .unwrap_or(std::ptr::null())
}
