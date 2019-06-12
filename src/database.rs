use rand::prelude::*;
use sha2::{Sha256, Digest};
use chrono::DateTime;
use chrono::offset::Utc;
use std::collections::HashMap;
use crate::security::{ProtectedString, ProtectedBinary};
use crate::vdict::VariantDict;
use crate::context::Context;
use crate::crypto::kdf::{KdfParameters};
use crate::memutil;
use crate::crypto::kdf;
use crate::error::Error;

/// Core password manager. Contains groups which themselves contain password entries.
pub struct PwDatabase {
    pub(crate) context: Box<Context>,
    pub(crate) data_cipher_uuid: PwUUID,
    pub(crate) compression_algorithm: PwCompressionAlgorithm,
    pub(crate) kdf_parameters: KdfParameters,
    pub(crate) public_custom_data: VariantDict,
    pub(crate) master_key: CompositeKey,

    pub name: String,
    pub description: String,
    pub default_username: String,

    /// Number of days until history entries are deleted in a database maintenance operation.
    pub maintenance_history_days: u32,

    pub name_changed: DateTime<Utc>,
    pub description_changed: DateTime<Utc>,
    pub settings_changed: DateTime<Utc>,
    pub default_username_changed: DateTime<Utc>,
}

impl PwDatabase {
    pub fn new() -> PwDatabase {
        let now = Utc::now();

        PwDatabase {
            context: Box::new(Context::new()),
            data_cipher_uuid: PwUUID::zero(),
            compression_algorithm: PwCompressionAlgorithm::None,
            kdf_parameters: KdfParameters::new(PwUUID::zero()),
            public_custom_data: VariantDict::new(),
            master_key: CompositeKey::new(),

            name: String::new(),
            description: String::new(),
            default_username: String::new(),

            maintenance_history_days: 365,

            name_changed: now.clone(),
            description_changed: now.clone(),
            settings_changed: now.clone(),
            default_username_changed: now.clone(),
        }
    }

    pub fn add_user_key(&mut self, key: UserKey) {
        self.master_key.add_user_key(key);
    }
}

/// A group containing subgroups and entries.
pub struct PwGroup {
}

/// A password entry. Consists of several fields like a title, user name, password, ect. Each
/// password entry has a unique UUID.
pub struct PwEntry {
    pub uuid: PwUUID,
    pub strings: HashMap<String, ProtectedString>,
    pub binaries: HashMap<String, ProtectedBinary>,
    pub icon: PwIcon,
    // @TODO In the original implementation this includes a reference to its parent. Not sure how I
    // want to implement that in Rust.
}

/// The standard size of a PwUUID in bytes.
pub const UUID_SIZE: usize = 16;

/// A UUID of a password entry or group. One created, these are no longer mutable.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct PwUUID([u8; UUID_SIZE]);

impl PwUUID {
    pub const SIZE: usize = 16;
    const ZERO: PwUUID = PwUUID([0u8; UUID_SIZE]);

    /// Wrap an array of bytes of the correct size in a PwUUID.
    pub const fn wrap(data: [u8; UUID_SIZE]) -> PwUUID {
        PwUUID(data)
    }

    pub fn from_slice(data: &[u8]) -> PwUUID {
        debug_assert!(data.len() >= UUID_SIZE, "source does not have enough bytes for a valid PwUUID");
        let mut uuid = PwUUID::zero();
        uuid.0.copy_from_slice(&data[0..UUID_SIZE]);
        uuid
    }

    /// Creates a UUID with all bytes set to zero.
    pub const fn zero() -> PwUUID {
        PwUUID::ZERO
    }

    /// Create a new random UUID.
    pub fn random() -> PwUUID {
        let mut rng = rand::thread_rng();
        let mut uuid = Self::zero();
        loop {
            rng.fill(&mut uuid.0);
            if !uuid.is_zero() {
                break
            }
        }
        uuid
    }

    pub fn is_zero(&self) -> bool {
        self.0 == PwUUID::ZERO.0
    }
}

impl Default for PwUUID {
    fn default() -> PwUUID {
        PwUUID::zero()
    }
}

impl std::fmt::Display for PwUUID {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let mut dest = [0u8; UUID_SIZE * 2];
        crate::memutil::to_hex_into_slice(&self.0, &mut dest);

        let mut first = true;
        for chunk in dest.chunks(UUID_SIZE / 2) {
            if first {
                write!(f, "{}", unsafe { std::str::from_utf8_unchecked(chunk) })?;
                first = false;
            } else {
                write!(f, "-{}", unsafe { std::str::from_utf8_unchecked(chunk) })?;
            }
        }

        Ok(())
    }
}

/// Master password/passphrase as provided by the user.
pub struct KcpPassword {
    /// Key data for the user password/passphrase.
    pub(crate) key_data: ProtectedBinary,

    /// The password as a string. This is None unless the password is set to be remembered during
    /// the construction of the KcpPassword.
    pub(crate) password: Option<ProtectedString>,
}

impl KcpPassword {
    pub fn new<S: Into<String>>(password: S, remember: bool) -> KcpPassword {
        let password = ProtectedString::wrap(password.into());
        let mut hasher = Sha256::new();
        hasher.input(password.as_bytes());
        let hash = hasher.result();

        let mut key_data = Vec::with_capacity(hash.len());
        key_data.resize(hash.len(), 0);
        (&mut key_data[0..]).copy_from_slice(&hash);

        KcpPassword {
            key_data: ProtectedBinary::wrap(key_data),
            password: if remember {
                Some(password)
            } else {
                None
            },
        }
    }

    pub fn is_valid_password(_pass: &str) -> bool {
        // @TODO this should make sure that the password is valid unicode and is normalized.
        // For now it just always returns true for all strings.
        true
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum UserKeyType {
    Password,
}

pub enum UserKey {
    Password(KcpPassword),
}

impl UserKey {
    pub fn get_key_data(&self) -> &[u8] {
        match self {
            &UserKey::Password(ref pwd) => &pwd.key_data,
        }
    }

    pub fn get_type(&self) -> UserKeyType {
        match self {
            &UserKey::Password(_) => UserKeyType::Password,
        }
    }
}

pub struct CompositeKey {
    user_keys: Vec<UserKey>,
}

impl CompositeKey {
    pub fn new() -> CompositeKey {
        CompositeKey {
            user_keys: Vec::new(),
        }
    }

    pub fn add_user_key(&mut self, user_key: UserKey) {
        self.user_keys.push(user_key);
    }

    pub fn find_type(&self, user_key_type: UserKeyType) -> Option<usize> {
        for (idx, ref user_key) in self.user_keys.iter().enumerate() {
            if user_key.get_type() == user_key_type {
                return Some(idx)
            }
        }
        return None;
    }

    pub fn contains_type(&self, user_key_type: UserKeyType) -> bool {
        self.find_type(user_key_type).is_some()
    }

    pub fn clear(&mut self) {
        self.user_keys.clear();
    }

    pub fn validate_user_keys(&self) -> Result<(), Error> {
        // @TODO for now this just returns true, but it should actually check that there is at most
        // one user account in the composite key list.

        Ok(())
    }

    /// Creates the composite key from the supplied user key sources (password, key file, user account, computer ID, ect.)
    pub fn create_raw_composite_key_32(&self) -> Result<ProtectedBinary, Error> {

        let _ = self.validate_user_keys()?;

        let mut data = Vec::new();
        for user_key in self.user_keys.iter() {
            data.extend_from_slice(user_key.get_key_data());
        }

        let mut hasher = Sha256::new();
        hasher.input(&data);
        let ret = ProtectedBinary::copy_slice(&hasher.result());

        memutil::zero_vec(&mut data);

        Ok(ret)
    }

    /// Generate a 32 byte (256-bit) composite key.
    pub fn generate_key_32(&self, params: &KdfParameters) -> Result<ProtectedBinary, Error> {
        let raw32 = self.create_raw_composite_key_32()?;
        debug_assert!(raw32.len() == 32, "Raw composite key did not have a length of 32.");

        let kdf = kdf::get_kdf_engine(&params.kdf_uuid).ok_or(Error::Generic("No KDF engine matching UUID"))?;

        let mut trf32 = kdf.transform(&raw32, &params)?;

        let ret = ProtectedBinary::copy_slice(&trf32);
        memutil::zero_slice(&mut trf32);
        Ok(ret)
    }
}

/// Compression algorithm specifiers.
pub enum PwCompressionAlgorithm {
    /// No compression algorithm.
    None = 0,

    /// GZip Compression
    GZip = 1,
}

impl PwCompressionAlgorithm {
    pub const fn count() -> u32 {
        2
    }

    pub fn from_int(n: u32) -> Option<PwCompressionAlgorithm> {
        match n {
            0 => Some(PwCompressionAlgorithm::None),
            1 => Some(PwCompressionAlgorithm::GZip),
            _ => None,
        }
    }
}

/// Tree traversal methods.
pub enum TraversalMethod {
    /// Don't traverse the tree.
    None = 0,

    /// Traverse the tree in pre-order mode, i.e. first visit all items in the current node, then
    /// visit all subnodes. (Breadth first)
    PreOrder = 1,
}

/// Methods for mergin databases/entries.
pub enum PwMergeMethod {
    None = 0,
    OverwriteExisting = 1,
    KeepExisting = 2,
    OverwriteIfNewer = 3,
    CreateNewUuids = 4,
    Synchronize = 5
}

/// Icon identifiers for groups and password entries.
pub enum PwIcon {
    Key = 0,
    World,
    Warning,
    NetworkServer,
    MarkedDirectory,
    UserCommunication,
    Parts,
    Notepad,
    WorldSocket,
    Identity,
    PaperReady,
    Digicam,
    IRCommunication,
    MultiKeys,
    Energy,
    Scanner,
    WorldStar,
    CDRom,
    Monitor,
    EMail,
    Configuration,
    ClipboardReady,
    PaperNew,
    Screen,
    EnergyCareful,
    EMailBox,
    Disk,
    Drive,
    PaperQ,
    TerminalEncrypted,
    Console,
    Printer,
    ProgramIcons,
    Run,
    Settings,
    WorldComputer,
    Archive,
    Homebanking,
    DriveWindows,
    Clock,
    EMailSearch,
    PaperFlag,
    Memory,
    TrashBin,
    Note,
    Expired,
    Info,
    Package,
    Folder,
    FolderOpen,
    FolderPackage,
    LockOpen,
    PaperLocked,
    Checked,
    Pen,
    Thumbnail,
    Book,
    List,
    UserKey,
    Tool,
    Home,
    Star,
    Tux,
    Feather,
    Apple,
    Wiki,
    Money,
    Certificate,
    BlackBerry,
    Count
}

pub enum ProxyServerType {
    None = 0,
    System = 1,
    Manual = 2,
}

pub enum ProxyAuthType {
    None = 0,

    /// Use default user credentials (provided by system)
    Default = 1,

    Manual = 2,

    /// `Default` or `Manual`, depending on whether manual credentials are available. This type
    /// exists for supporting upgrading from KeePass 2.28 to 2.29; the user cannot select this
    /// type.
    Auto = 3
}

/// Comparison modes for in-memory protected objects.
pub enum MemProtCmpMode {
    /// Ignore the in-memory protection states.
    None = 0,

    /// Ignore the in-memory protection states of standard objects; do compare in-memory protection
    /// states of custom objects.
    CustomOnly,

    /// Compare in-memory protection states.
    Full,
}
