use std::fmt;

pub const KEEPASS_VERSION_1X: &str = "KeePass 1.x";

pub enum Error {
    // Sometimes I use this as a placeholder.
    /// A generic error that carries a message but isn't really recoverable or actionable.
    Generic(&'static str),

    /// An error that occurred while doing IO (e.g. a file not existing).
    IO(std::io::Error),

    /// A KDBX file being laoded is using a format of the file that is too old to be loaded.
    OldFormat(&'static str),

    /// A KDBX file had an invalid file signature in the header.
    InvalidSignature((u32, u32)),

    /// A KDBX file had a version that is not supported.
    UnsupportedFileVersion(u32),

    /// A KDBX file has some invalid bits in it.
    BadFormat(&'static str),

    // @TODO maybe add the xml error text in here, but that might leak something.
    /// XML error.
    XmlError,
}

impl fmt::Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            &Error::Generic(message) => {
                write!(f, "Error::Generic({})", message)
            },

            &Error::IO(ref source) => {
                write!(f, "Error::IO({:?})", source)
            },

            &Error::OldFormat(version) => {
                write!(f, "Error::OldFormatVersion({})", version)
            },

            &Error::InvalidSignature(signature) => {
                write!(f, "Error::InvalidSignature({:?})", signature)
            },

            &Error::UnsupportedFileVersion(version) => {
                write!(f, "Error::UnsupportedFileVersion({})", version)
            },

            &Error::BadFormat(desc) => {
                write!(f, "Error::BadFormat({})", desc)
            },

            &Error::XmlError => {
                write!(f, "Error::XmlError")
            },
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            &Error::Generic(message) => {
                write!(f, "Error `{}`", message)
            },

            &Error::IO(ref source) => {
                write!(f, "IO Error `{}`", source)
            },

            &Error::OldFormat(version) => {
                write!(f, "Old Format `version {}`", version)
            },

            &Error::InvalidSignature(signature) => {
                write!(f, "Invalid Signature `signature 0x{:08X}, 0x{:08X}`", signature.0, signature.1)
            },

            &Error::UnsupportedFileVersion(version) => {
                write!(f, "Unsupported File Version `{}`", version)
            },

            &Error::BadFormat(desc) => {
                write!(f, "Bad File Format `{}`", desc)
            },

            &Error::XmlError => {
                write!(f, "XML Error")
            },
        }
    }
}

impl std::error::Error for Error {
}
