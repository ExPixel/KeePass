#![allow(dead_code, unused_imports)]

/// Temporary logging while I'm writing the library
macro_rules! debug_println {
    ($fmt:expr) => {
        println!(concat!("[DEBUG] ", $fmt));
    };

    ($fmt:expr, $($args:tt)*) => {
        println!(concat!("[DEBUG] ", $fmt), $($args)*);
    };
}

pub mod error;
pub mod database;
mod memutil;
mod ioutil;
pub mod kdbx;
pub mod vdict;
pub mod context;
pub mod constants;
pub mod crypto;
pub mod cryptoutil;
pub mod security;

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        println!("uuid: {}", super::database::PwUUID::random());
        assert_eq!(2 + 2, 4);
    }
}
