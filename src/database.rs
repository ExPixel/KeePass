use std::cell::RefCell;
use std::rc::{Rc, Weak};
use crate::constants;
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

pub type WrappedPwGroup = Rc<RefCell<PwGroup>>;
pub type WrappedPwEntry = Rc<RefCell<PwEntry>>;

pub type Color = (u8, u8, u8, u8);
pub const COLOR_ZERO: Color = (0, 0, 0, 0);

#[inline]
fn default_time() -> DateTime<Utc> {
    chrono::MIN_DATE.and_hms(0, 0, 0)
}

/// Core password manager. Contains groups which themselves contain password entries.
pub struct PwDatabase {
    pub(crate) context: Box<Context>,

    /// Tne encryption algorithm used to encrypt the data part of the database.
    pub(crate) data_cipher_uuid: PwUUID,

    /// The compression algorithm used to compress the data part of teh database.
    pub(crate) compression_algorithm: PwCompressionAlgorithm,

    /// Contains the number of key transformation rounds for the KDF.
    pub(crate) kdf_parameters: KdfParameters,

    pub(crate) master_key: CompositeKey,

    pub root_group: Rc<RefCell<PwGroup>>,

    /// Memory protection configuration for default fields.
    pub memory_protection: MemoryProtectionConfig,

    pub name: String,
    pub name_changed: DateTime<Utc>,

    pub description: String,
    pub description_changed: DateTime<Utc>,

    pub default_username: String,
    pub default_username_changed: DateTime<Utc>,

    /// Color in the form (R, G, B, A)
    pub color: Color,

    /// Number of days until history entries are deleted in a database maintenance operation.
    pub maintenance_history_days: u32,
    pub settings_changed: DateTime<Utc>,

    pub recycle_bin_enabled: bool,
    pub recycle_bin_changed: DateTime<Utc>,
    pub recycle_bin_uuid: PwUUID,

    pub master_key_changed: DateTime<Utc>,
    pub master_key_change_rec: i64,
    pub master_key_change_force: i64,
    pub master_key_change_force_once: bool,

    pub entry_templates_group: PwUUID,
    pub entry_templates_group_changed: DateTime<Utc>,

    pub last_selected_group: PwUUID,
    pub last_top_visible_group: PwUUID,

    pub history_max_items: i32,
    pub history_max_size: i64,

    /// Custom data container that can be used by plugins to store own data in KeePass databases.
    /// The data here is stored in teh encrypted part of the encrypted database file.
    pub custom_data: HashMap<String, String>,

    /// All custom icons stored in this database.
    pub custom_icons: Vec<PwCustomIcon>,

    /// Custom data container that can be used by plguins to store their own data in KeePass
    /// databases. The data is stored in the *unencrypted* part of database files, and it is not
    /// supported by all file formats (e.g. supported by KDBX, unsupported by XML.)
    /// It is highly recommended to use `custom_data` instead, if possible.
    pub public_custom_data: VariantDict,

    /// Hash value of the primary file on disk (last read or last write).
    pub hash_of_file_on_disk: [u8; 32],
    pub hash_of_last_io: [u8; 32],

    pub use_file_locks: bool,
    pub use_file_transactions: bool,
    pub detach_binaries: bool,

    pub deleted_objects: Vec<PwDeletedObject>,
}

impl PwDatabase {
    pub fn new() -> PwDatabase {
        PwDatabase {
            context: Box::new(Context::new()),
            data_cipher_uuid: PwUUID::zero(),
            compression_algorithm: PwCompressionAlgorithm::None,
            kdf_parameters: KdfParameters::new(PwUUID::zero()),
            master_key: CompositeKey::new(),
            memory_protection: MemoryProtectionConfig::default(),
            name: String::new(),
            description: String::new(),
            default_username: String::new(),
            color: (0, 0, 0, 0),
            maintenance_history_days: 365,
            master_key_change_rec: -1,
            master_key_change_force: -1,
            master_key_change_force_once:  false,
            name_changed: default_time(),
            description_changed: default_time(),
            settings_changed: default_time(),
            default_username_changed: default_time(),
            master_key_changed: default_time(),
            recycle_bin_changed: default_time(),
            entry_templates_group: PwUUID::zero(),
            entry_templates_group_changed: default_time(),
            deleted_objects: Vec::new(),
            recycle_bin_uuid: PwUUID::zero(),
            history_max_items: constants::DEFAULT_HISTORY_MAX_ITEMS,
            history_max_size: constants::DEFAULT_HISTORY_MAX_SIZE,
            custom_data: HashMap::new(),
            custom_icons: Vec::new(),
            public_custom_data: VariantDict::new(),
            hash_of_file_on_disk: [0u8; 32],
            hash_of_last_io: [0u8; 32],
            use_file_locks: false,
            use_file_transactions: false,
            detach_binaries: false,
            recycle_bin_enabled: false,
            last_selected_group: PwUUID::zero(),
            last_top_visible_group: PwUUID::zero(),
            root_group: PwGroup::default().wrap(),
        }
    }

    pub fn add_user_key(&mut self, key: UserKey) {
        self.master_key.add_user_key(key);
    }
}

/// A group containing subgroups and entries.
pub struct PwGroup {
    /// Parent group of this group.
    pub parent: Option<Weak<RefCell<PwGroup>>>,

    /// A list of subgroups in this group.
    pub groups: Vec<Rc<RefCell<PwGroup>>>,

    /// A list of entries in this group.
    pub entries: Vec<Rc<RefCell<PwEntry>>>,

    /// UUID of this group.
    pub uuid: PwUUID,

    /// Name of this group.
    pub name: String,

    /// Comments about this group.
    pub notes: String,

    /// Icon of this group.
    pub icon: PwIcon,

    /// Get the custom icon ID. This value is 0, if no custom icon is
    /// being used (i.e. the icon specified by the `IconID` property
    /// should be displayed).
    pub custom_icon_uuid: PwUUID,

    /// The date/time when the location of the group was last changed.
    pub location_changed: DateTime<Utc>,


    /// A flag that specifies if the group is shown as expanded or
    /// collapsed in the user interface.
    pub(crate) is_expanded: bool,

    /// The date/time when this group was created.
    pub creation_time: DateTime<Utc>,

    /// The date/time when this group was last modified.
    pub last_modification_time: DateTime<Utc>,

    /// The date/time when this group was last accessed (read).
    pub last_access_time: DateTime<Utc>,

    /// The date/time when this group expires.
    pub expiry_time: DateTime<Utc>,

    /// Flag that determines if this group expires.
    pub expires: bool,

    /// To increase the usage count, use the `touch` function.
    pub usage_count: u64,

    /// A flag specifying whether this group is virtual or not. Virtual
    /// groups can contain links to entries stored in other groups.
    /// Note that this flag has to be interpreted and set by the calling
    /// code; it won't prevent you from accessing and modifying the list
    /// of entries in this group in any way.
    pub is_virtual: bool,

    /// Default auto-type keystroke sequence for all entries in
    /// this group. This property can be an empty string, which
    /// means that the value should be inherited from the parent.
    pub default_autotype_sequence: String,

    pub enable_autotype: Option<bool>,
    pub enable_searching: Option<bool>,
    pub last_top_visible_entry: PwUUID,

    /// Custom data container that can be used by plugins to store
    /// own data in KeePass groups.
    /// The data is stored in the encrypted part of encrypted
    /// database files.
    /// Use unique names for your items, e.g. "PluginName_ItemName".
    pub custom_data: HashMap<String, String>,
}

impl PwGroup {
    pub const DEFAULT_AUTOTYPE_ENABLED: bool = true;
    pub const DEFAULT_SEARCHING_ENABLED: bool = true;
    pub const MAX_DEPTH: usize = 126;

    /// Create a new PwGroup and initialize the UUID and the times.
    pub fn init() -> PwGroup {
        PwGroup::new(true, true, PwIcon::Folder)
    }

    pub fn new(create_new_uuid: bool, set_times: bool, icon: PwIcon) -> PwGroup {
        let uuid = if create_new_uuid {
            PwUUID::random()
        } else {
            PwUUID::zero()
        };

        let time = if set_times {
            Utc::now()
        } else {
            default_time()
        };

        PwGroup {
            parent: None,
            groups: Vec::new(),
            entries: Vec::new(),
            uuid: uuid,
            name: String::new(),
            notes: String::new(),
            icon: icon,
            custom_icon_uuid: PwUUID::zero(),
            location_changed: time.clone(),
            is_expanded: true,
            creation_time: time.clone(),
            last_modification_time: time.clone(),
            last_access_time: time.clone(),
            expiry_time: time.clone(),
            expires: false,
            usage_count: 0,
            is_virtual: false,
            default_autotype_sequence: String::new(),
            enable_autotype: None,
            enable_searching: None,
            last_top_visible_entry: PwUUID::zero(),
            custom_data: HashMap::new(),
        }
    }

    /// Initialize all of the timestamps to the current time.
    pub fn init_timestamps(&mut self) {
        let now = Utc::now();
        self.creation_time = now.clone();
        self.last_modification_time = now.clone();
        self.last_access_time = now.clone();
        self.location_changed = now.clone();
    }

    pub fn add_entry(this: &Rc<RefCell<Self>>, entry: Rc<RefCell<PwEntry>>, take_ownership: bool, update_location_changed_of_entry: bool) {
        if take_ownership {
            entry.borrow_mut().parent_group = Some(Rc::downgrade(this));
        }

        if update_location_changed_of_entry {
            entry.borrow_mut().location_changed = Utc::now();
        }

        this.borrow_mut().entries.push(entry);

        println!("ADDED ENTRY TO GROUP>");
    }

    pub fn add_group(this: &Rc<RefCell<Self>>, sub_group: Rc<RefCell<PwGroup>>, take_ownership: bool, update_location_changed_of_entry: bool) {
        if take_ownership {
            sub_group.borrow_mut().parent = Some(Rc::downgrade(this));
        }

        if update_location_changed_of_entry {
            sub_group.borrow_mut().location_changed = Utc::now();
        }

        this.borrow_mut().groups.push(sub_group);
    }

    #[inline]
    pub fn wrap(self) -> Rc<RefCell<PwGroup>> {
        Rc::new(RefCell::new(self))
    }
}

impl Default for PwGroup {
    fn default() -> PwGroup {
        PwGroup::new(false, false, PwIcon::Folder)
    }
}

/// A password entry. Consists of several fields like a title, user name, password, ect. Each
/// password entry has a unique UUID.
pub struct PwEntry {
    /// UUID of this entry.
    pub uuid: PwUUID,

    /// Reference to the parent group that contains this entry.
    pub parent_group: Option<Weak<RefCell<PwGroup>>>,

    /// The date/time when the location of this entry was last changed.
    pub location_changed: DateTime<Utc>,

    /// All strings associated with this entry.
    pub strings: HashMap<String, ProtectedString>,

    /// All binaries associated with this entry.
    pub binaries: HashMap<String, ProtectedBinary>,

    /// Auto-type Window/Keystroke sequence associations.
    pub auto_type: AutoTypeConfig,

    /// Previous versions of this entry.
    pub history: Vec<Rc<RefCell<PwEntry>>>,

    /// Image ID specifying the icon that will be used for this entry.
    pub icon: PwIcon,

    /// The custom icon ID for this entry. This value is 0 if no custom icon is being used.
    pub custom_icon_uuid: PwUUID,

    /// The foreground color of this entry.
    pub foreground_color: Color,

    /// The background color of this entry.
    pub background_color: Color,

    /// The date/time when this entry was created.
    pub creation_time: DateTime<Utc>,

    /// The date/time when this entry was last modified (written to).
    pub last_modification_time: DateTime<Utc>,

    /// The date/time when this entry was last accessed (read from).
    pub last_access_time: DateTime<Utc>,

    /// The date/time when this entry expires.
    pub expiry_time: DateTime<Utc>,

    /// Specifies whether the entry expires or not.
    pub expires: bool,

    /// The usage count of this entry. Increment this counter by using the `touch` method.
    pub usage_count: u64,

    /// Entry-specific override URL if this string is not empty.
    pub override_url: String,

    /// List of tags associated with this entry.
    pub tags: Vec<String>,

    /// Custom data container that can be used by plugins to store
    /// own data in KeePass entries.
    /// The data is stored in the encrypted part of encrypted
    /// database files.
    /// Use unique names for your items, e.g. "PluginName_ItemName".
    pub custom_data: HashMap<String, String>,
}

impl PwEntry {
    pub fn new(parent_group: Option<Weak<RefCell<PwGroup>>>, create_new_uuid: bool, set_times: bool) -> PwEntry {
        let uuid = if create_new_uuid {
            PwUUID::random()
        } else {
            PwUUID::zero()
        };

        let time = if set_times {
            Utc::now()
        } else {
            default_time()
        };

        PwEntry {
            uuid: uuid,
            parent_group: parent_group,
            location_changed: time.clone(),
            strings: HashMap::new(),
            binaries: HashMap::new(),
            auto_type: AutoTypeConfig::new(),
            history: Vec::new(),
            icon: PwIcon::Key,
            custom_icon_uuid: PwUUID::zero(),
            foreground_color: COLOR_ZERO,
            background_color: COLOR_ZERO,
            creation_time: time.clone(),
            last_modification_time: time.clone(),
            last_access_time: time.clone(),
            expiry_time: time.clone(),
            expires: false,
            usage_count: 0,
            override_url: String::new(),
            tags: Vec::new(),
            custom_data: HashMap::new(),
        }
    }

    /// Initialize all of the timestamps to the current time.
    pub fn init_timestamps(&mut self) {
        let now = Utc::now();
        self.creation_time = now.clone();
        self.last_modification_time = now.clone();
        self.last_access_time = now.clone();
        self.location_changed = now.clone();
    }

    #[inline]
    pub fn wrap(self) -> Rc<RefCell<PwEntry>> {
        Rc::new(RefCell::new(self))
    }
}

impl Default for PwEntry {
    fn default() -> PwEntry {
        PwEntry::new(None, false, false)
    }
}


/// A list of auto-type associations.
#[derive(Clone, PartialEq, Eq)]
pub struct AutoTypeConfig {
    /// Specify whether the auto-type is enabled or not.
    pub enabled: bool,
    /// Specify whether the typing should be obfuscated.
    pub obfuscation_options: AutoTypeObfuscationOptions,
    /// The default keystroke sequence that is auto-typed if no matching window is found in the
    /// `associations` vector.
    pub default_sequence: String,
    /// Get all auto-type window/keystroke pairs.
    pub associations: Vec<AutoTypeAssociation>,
}

impl AutoTypeConfig {
    pub fn new() -> AutoTypeConfig {
        AutoTypeConfig {
            enabled: true,
            obfuscation_options: AutoTypeObfuscationOptions::None,
            default_sequence: String::new(),
            associations: Vec::new(),
        }
    }

    pub fn add(&mut self, assoc: AutoTypeAssociation) {
        self.associations.push(assoc);
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct AutoTypeAssociation {
    window: String,
    sequence: String,
}

impl AutoTypeAssociation {
    pub fn new(window: String, sequence: String) -> AutoTypeAssociation {
        AutoTypeAssociation { window, sequence }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum AutoTypeObfuscationOptions {
    None = 0,
    UseClipboard = 1,
}

impl AutoTypeObfuscationOptions {
    pub fn from_int(n: u32) -> Option<AutoTypeObfuscationOptions> {
        match n {
            0 => Some(AutoTypeObfuscationOptions::None),
            1 => Some(AutoTypeObfuscationOptions::UseClipboard),
            _ => None,
        }
    }

    pub fn to_int(self) -> u32 {
        match self {
            AutoTypeObfuscationOptions::None => 0,
            AutoTypeObfuscationOptions::UseClipboard => 1,
        }
    }
}

/// Represents an object that has been deleted.
#[derive(Clone)]
pub struct PwDeletedObject {
    /// UUID of the object that has been deleted.
    pub uuid: PwUUID,

    /// The date/time when the object was deleted.
    pub deletion_time: DateTime<Utc>,
}

impl PwDeletedObject {
    pub fn new(uuid: PwUUID, deletion_time: DateTime<Utc>) -> PwDeletedObject {
        PwDeletedObject { uuid, deletion_time }
    }
}

impl Default for PwDeletedObject {
    fn default() -> PwDeletedObject {
        PwDeletedObject::new(PwUUID::ZERO, default_time())
    }
}

/// The standard size of a PwUUID in bytes.
pub const UUID_SIZE: usize = 16;

/// A UUID of a password entry or group. One created, these are no longer mutable.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct PwUUID([u8; UUID_SIZE]);

impl PwUUID {
    pub const SIZE: usize = 16;
    pub const ZERO: PwUUID = PwUUID([0u8; UUID_SIZE]);

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

#[derive(Default, Clone)]
pub struct MemoryProtectionConfig {
    pub protect_title: bool,
    pub protect_username: bool,
    pub protect_password: bool,
    pub protect_url: bool,
    pub protect_notes: bool,
}

impl MemoryProtectionConfig {
    pub fn is_protected(&self, field: &str) -> bool {
        match field {
            constants::TITLE_FIELD => self.protect_title,
            constants::USERNAME_FIELD => self.protect_username,
            constants::PASSWORD_FIELD => self.protect_password,
            constants::URL_FIELD => self.protect_url,
            constants::NOTES_FIELD => self.protect_notes,
            _ => false,
        }
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
#[derive(Copy, Clone)]
#[repr(u32)]
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
    Count,
}

impl PwIcon {
    pub fn from_int(n: u32) -> Option<PwIcon> {
        // @TODO replace this with a safer implementation
        unsafe {
            let count = std::mem::transmute::<PwIcon, u32>(PwIcon::Count);
            if n < count {
                Some(std::mem::transmute::<u32, PwIcon>(n))
            } else {
                None
            }
        }
    }

    pub fn to_int(self) -> u32 {
        // @TODO replace this with a safer implementation
        unsafe {
            std::mem::transmute(self)
        }
    }
}

/// A custom icon.
pub struct PwCustomIcon {
    uuid: PwUUID,
    image_data_png: Vec<u8>,
}

impl PwCustomIcon {
    pub const MAX_WIDTH: u32 = 128;
    pub const MAX_HEIGHT: u32 = 128;

    pub fn new(uuid: PwUUID, image_data_png: Vec<u8>) -> PwCustomIcon {
        PwCustomIcon { uuid, image_data_png }
    }
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
