pub mod read;
pub mod write;

pub use self::read::*;
pub use self::write::*;

#[derive(Copy, Clone, PartialEq, Eq)]
pub enum KdbxFormat {
    /// The default, encrypted file format.
    Default = 0,

    /// Use this flag when exporting data to a plain-text XML file.
    PlainXml = 1,
}


/// File Identifier
const FILE_SIGNATURE: (u32, u32) = (0x9AA2D903, 0xB54BFB67);

/// File version of files saved by the current kdbx file module.
/// The first 2 bytes are critical (i.e. loading will fail, if the file version is too high), the
/// last 2 bytes are informational.
const FILE_VERSION_32: u32 = 0x00040000;
/// First of 4.x series
const FILE_VERSION_32_4: u32 = 0x00040000;
/// Old format 3.1
const FILE_VERSION_32_3: u32 = 0x00030001;
const FILE_VERSION_CRITICAL_MASK: u32 = 0xFFFF0000;

/// KeePass 1.x Signature
const FILE_SIGNATURE_OLD: (u32, u32) = (0x9AA2D903, 0xB54BFB65);
/// KeePass 2.x pre-release (alpha and beta) signature
const FILE_SIGNATURE_PRE_RELEASE: (u32, u32) = (0x9AA2D903, 0xB54BFB66);

const ELEM_DOC_NODE: &str = "KeePassFile";
const ELEM_META: &str = "Meta";
const ELEM_ROOT: &str = "Root";
const ELEM_GROUP: &str = "Group";
const ELEM_ENTRY: &str = "Entry";

const ELEM_GENERATOR: &str = "Generator";
const ELEM_HEADER_HASH: &str = "HeaderHash";
const ELEM_SETTINGS_CHANGED: &str = "SettingsChanged";
const ELEM_DB_NAME: &str = "DatabaseName";
const ELEM_DB_NAME_CHANGED: &str = "DatabaseNameChanged";
const ELEM_DB_DESC: &str = "DatabaseDescription";
const ELEM_DB_DESC_CHANGED: &str = "DatabaseDescriptionChanged";
const ELEM_DB_DEFAULT_USER: &str = "DefaultUserName";
const ELEM_DB_DEFAULT_USER_CHANGED: &str = "DefaultUserNameChanged";
const ELEM_DB_MNTNC_HISTORY_DAYS: &str = "MaintenanceHistoryDays";
const ELEM_DB_COLOR: &str = "Color";
const ELEM_DB_KEY_CHANGED: &str = "MasterKeyChanged";
const ELEM_DB_KEY_CHANGE_REC: &str = "MasterKeyChangeRec";
const ELEM_DB_KEY_CHANGE_FORCE: &str = "MasterKeyChangeForce";
const ELEM_DB_KEY_CHANGE_FORCE_ONCE: &str = "MasterKeyChangeForceOnce";
const ELEM_RECYCLE_BIN_ENABLED: &str = "RecycleBinEnabled";
const ELEM_RECYCLE_BIN_UUID: &str = "RecycleBinUUID";
const ELEM_RECYCLE_BIN_CHANGED: &str = "RecycleBinChanged";
const ELEM_ENTRY_TEMPLATES_GROUP: &str = "EntryTemplatesGroup";
const ELEM_ENTRY_TEMPLATES_GROUP_CHANGED: &str = "EntryTemplatesGroupChanged";
const ELEM_HISTORY_MAX_ITEMS: &str = "HistoryMaxItems";
const ELEM_HISTORY_MAX_SIZE: &str = "HistoryMaxSize";
const ELEM_LAST_SELECTED_GROUP: &str = "LastSelectedGroup";
const ELEM_LAST_TOP_VISIBLE_GROUP: &str = "LastTopVisibleGroup";

const ELEM_MEMORY_PROT: &str = "MemoryProtection";
const ELEM_PROT_TITLE: &str = "ProtectTitle";
const ELEM_PROT_USER_NAME: &str = "ProtectUserName";
const ELEM_PROT_PASSWORD: &str = "ProtectPassword";
const ELEM_PROT_URL: &str = "ProtectURL";
const ELEM_PROT_NOTES: &str = "ProtectNotes";

const ELEM_CUSTOM_ICONS: &str = "CustomIcons";
const ELEM_CUSTOM_ICON_ITEM: &str = "Icon";
const ELEM_CUSTOM_ICON_ITEM_ID: &str = "UUID";
const ELEM_CUSTOM_ICON_ITEM_DATA: &str = "Data";

const ELEM_AUTO_TYPE: &str = "AutoType";
const ELEM_HISTORY: &str = "History";

const ELEM_NAME: &str = "Name";
const ELEM_NOTES: &str = "Notes";
const ELEM_UUID: &str = "UUID";
const ELEM_ICON: &str = "IconID";
const ELEM_CUSTOM_ICON_ID: &str = "CustomIconUUID";
const ELEM_FG_COLOR: &str = "ForegroundColor";
const ELEM_BG_COLOR: &str = "BackgroundColor";
const ELEM_OVERRIDE_URL: &str = "OverrideURL";
const ELEM_TIMES: &str = "Times";
const ELEM_TAGS: &str = "Tags";

const ELEM_CREATION_TIME: &str = "CreationTime";
const ELEM_LAST_MOD_TIME: &str = "LastModificationTime";
const ELEM_LAST_ACCESS_TIME: &str = "LastAccessTime";
const ELEM_EXPIRY_TIME: &str = "ExpiryTime";
const ELEM_EXPIRES: &str = "Expires";
const ELEM_USAGE_COUNT: &str = "UsageCount";
const ELEM_LOCATION_CHANGED: &str = "LocationChanged";

const ELEM_GROUP_DEFAULT_AUTO_TYPE_SEQ: &str = "DefaultAutoTypeSequence";
const ELEM_ENABLE_AUTO_TYPE: &str = "EnableAutoType";
const ELEM_ENABLE_SEARCHING: &str = "EnableSearching";

const ELEM_STRING: &str = "String";
const ELEM_BINARY: &str = "Binary";
const ELEM_KEY: &str = "Key";
const ELEM_VALUE: &str = "Value";

const ELEM_AUTO_TYPE_ENABLED: &str = "Enabled";
const ELEM_AUTO_TYPE_OBFUSCATION: &str = "DataTransferObfuscation";
const ELEM_AUTO_TYPE_DEFAULT_SEQ: &str = "DefaultSequence";
const ELEM_AUTO_TYPE_ITEM: &str = "Association";
const ELEM_WINDOW: &str = "Window";
const ELEM_KEYSTROKE_SEQUENCE: &str = "KeystrokeSequence";

const ELEM_BINARIES: &str = "Binaries";

const ATTR_ID: &str = "ID";
const ATTR_REF: &str = "Ref";
const ATTR_PROTECTED: &str = "Protected";
const ATTR_PROTECTED_IN_MEM_PLAIN_XML: &str = "ProtectInMemory";
const ATTR_COMPRESSED: &str = "Compressed";

const ELEM_IS_EXPANDED: &str = "IsExpanded";
const ELEM_LAST_TOP_VISIBLE_ENTRY: &str = "LastTopVisibleEntry";

const ELEM_DELETED_OBJECTS: &str = "DeletedObjects";
const ELEM_DELETED_OBJECT: &str = "DeletedObject";
const ELEM_DELETION_TIME: &str = "DeletionTime";

const VAL_FALSE: &str = "False";
const VAL_TRUE: &str = "True";

const ELEM_CUSTOM_DATA: &str = "CustomData";
const ELEM_STRING_DICT_EX_ITEM: &str = "Item";

bitflags::bitflags! {
    struct KdbxHeaderFieldID: u8 {
        const END_OF_HEADER = 0;
        const COMMENT = 1;
        const CIPHER_ID = 2;
        const COMPRESSION_FLAGS = 3;
        const MASTER_SEED = 4;
        const TRANSFORM_SEED = 5; // KDBX 3.1, for backword compatibility only
        const TRANSFORM_ROUNDS = 6; // KDBX 3.1, for backward compatibility only
        const ENCRYPTION_IV = 7;
        const INNER_RANDOM_STREAM_KEY = 8;
        const STREAM_START_BYTES = 9; // KDBX 3.1, for backward compatibility only
        const INNER_RANDOM_STREAM_ID = 10; // KDBX 3.1, for backward compatibility only
        const KDF_PARAMETERS = 11;
        const PUBLIC_CUSTOM_DATA = 12; // KDBX 4
    }
}

bitflags::bitflags! {
    struct KdbxInnerHeaderFieldID: u8 {
        const END_OF_HEADER = 0;
        const INNER_RANDOM_STREAM_ID = 1; // Supersedes KdbxHeaderFieldID.InnerRandomStreamID
        const INNER_RANDOM_STREAM_KEY = 2; // Supersedes KdbxHeaderFieldID.InnerRandomStreamKey
        const BINARY = 3;
    }
}

bitflags::bitflags! {
    struct KdbxBinaryFlags: u8 {
        const NONE = 0;
        const PROTECTED = 1;
    }
}
