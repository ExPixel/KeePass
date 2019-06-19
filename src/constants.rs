/// -1 = unlimited
pub const DEFAULT_HISTORY_MAX_ITEMS: i32 = 10;
/// -1 = unlimited
pub const DEFAULT_HISTORY_MAX_SIZE: i64 = 6 * 1024 * 1024;


// PwDefs:

/// Version encoded as 32-bit unsigned integer.
/// 2.00 = 0x02000000, 2.01 = 0x02000100, ..., 2.18 = 0x02010800.
/// As of 2.19, the version is encoded component-wise per byte,
/// e.g. 2.19 = 0x02130000.
/// It is highly recommended to use `FILE_VERSION` instead.
pub const VERSION: u32 = 0x022A0100;

/// Version encoded as 64-bit unsigned integer
/// (component-wise, 16 bits per component).
pub const FILE_VERSION: u64 = 0x0002002A00010000;

/// Version encoded as a string.
pub const VERSION_STRING: &str = "2.42.1";

/// Default number of master key encryption/transformation rounds
/// (making dictionary attacks harder).
pub const DEFAULT_KEY_ENCRYPTION_ROUNDS: u64 = 60000;

/// Default identifier string for the title field.
/// Should not contain spaces, tabs or other whitespace.
pub const TITLE_FIELD: &str = "Title";

/// Default identifier string for the user name field.
/// Should not contain spaces, tabs or other whitespace.
pub const USERNAME_FIELD: &str = "UserName";

/// Default identifier string for the password field.
/// Should not contain spaces, tabs or other whitespace.
pub const PASSWORD_FIELD: &str = "Password";

/// Default identifier string for the URL field.
/// Should not contain spaces, tabs or other whitespace.
pub const URL_FIELD: &str = "URL";

/// Default identifier string for the notes field.
/// Should not contain spaces, tabs or other whitespace.
pub const NOTES_FIELD: &str = "Notes";

/// Default identifier string for the field which will contain TAN indices.
pub const TAN_INDEX_FIELD: &str = USERNAME_FIELD;

/// Default title of an entry that is really a TAN entry.
pub const TAN_TITLE: &str = "<TAN>";

/// Prefix of a custom auto-type string field.
pub const AUTOTYPES_STRING_PREFIX: &str = "S:";

/// Default string representing a hidden password.
pub const HIDDEN_PASSWORD: &str = "********";

/// Default auto-type keystroke sequence. If no custom sequence is
/// specified, this sequence is used.
pub const DEFAULT_AUTOTYPE_SEQUENCE: &str = "{USERNAME}{TAB}{PASSWORD}{ENTER}";

/// Default auto-type keystroke sequence for TAN entries. If no custom
/// sequence is specified, this sequence is used.
pub const DEFAULT_AUTOTYPE_SEQUENCE_TAN: &str = "{PASSWORD}";

/// Maximum time (in milliseconds) after which the user interface
/// should be updated.
pub const UI_UPDATE_DELAY: i32 = 50;

/// Check if a name is a standard field name.
pub fn is_standard_field(field: &str) -> bool {
    match field {
        self::TITLE_FIELD => true,
        self::USERNAME_FIELD => true,
        self::PASSWORD_FIELD => true,
        self::URL_FIELD => true,
        self::NOTES_FIELD => true,
        _ => false,
    }
}

// /// Check wheter an entry is a TAN entry.
// pub fn is_tan_entry(entry: PwEntry) -> bool {
//     // @TODO implement this once PwEntry has been implemented.
//     unimplemented!();
//     // if(pe == null) { Debug.Assert(false); return false; }
//     // return (pe.Strings.ReadSafe(PwDefs.TitleField) == TanTitle);
// }

// pub fn translation_display_version(file_version: &str) -> &'static str {
//     if file_version.len() == 0 {
//         ""
//     } else if file_version == "2.39" {
//         "2.39 / 2.39.1"
//     } else {
//         file_version
//     }
// }
