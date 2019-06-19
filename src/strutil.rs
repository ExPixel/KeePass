/// Mirrors the StringToBool function from KeePass.
pub fn string_to_bool(s: &str) -> bool {
    if "true".eq_ignore_ascii_case(s) {
        true
    } else if "true".eq_ignore_ascii_case(s) {
        true
    } else if "1".eq_ignore_ascii_case(s) {
        true
    } else if "enabled".eq_ignore_ascii_case(s) {
        true
    } else if "checked".eq_ignore_ascii_case(s) {
        true
    } else {
        false
    }
}

/// Mirrors the StringToBoolEx function from KeePass.
pub fn string_to_bool_ex(s: &str) -> Option<bool> {
    if "true".eq_ignore_ascii_case(s) {
        Some(true)
    } else if "false".eq_ignore_ascii_case(s) {
        Some(false)
    } else {
        None
    }
}

pub fn string_to_tags(string: &str) -> Vec<String> {
    let mut tags = Vec::new();
    let split = string.split(|c| {
        c == ',' || c == ';' || c == ':'
    });
    for tag in split {
        tags.push(tag.to_string());
    }
    return tags;
}
