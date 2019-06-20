extern crate cc;
extern crate bindgen;

use std::env;
use std::path::PathBuf;

pub fn main() {
    let argon2_root = PathBuf::from(".").join("phc-winner-argon2");
    let argon2_src = argon2_root.join("src");
    let blake2_src = argon2_src.join("blake2");

    let source_files = [
        // ARGON2 Source Files:
        argon2_src.join("argon2.c"),
        argon2_src.join("core.c"),
        argon2_src.join("thread.c"),
        argon2_src.join("encoding.c"),
        argon2_src.join("opt.c"),

        // BLAKE2 Source Files:
        blake2_src.join("blake2b.c"),
    ];

    let header_dirs = [
        argon2_root.join("include"),
        argon2_src.clone(),
    ];

    let mut build = cc::Build::new();
    build.cpp(false); // Build using C
    source_files.iter().for_each(|f| { build.file(&f); });
    header_dirs.iter().for_each(|d| { build.include(&d); });
    build.compile("libargon2");

    let bindings = bindgen::Builder::default()
        .header(
            argon2_root
                .join("include")
                .join("argon2.h")
                .to_str()
                .expect("Failed to convert path to string.")
        )
        .whitelist_type("Argon2_Context")
        .whitelist_type("Argon2_type")
        .whitelist_type("Argon2_version")
        .whitelist_type("Argon2_ErrorCodes")
        .whitelist_function("argon2_type2string")
        .whitelist_function("argon2_ctx")
        .whitelist_function("argon2i_hash_encoded")
        .whitelist_function("argon2i_hash_raw")
        .whitelist_function("argon2d_hash_encoded")
        .whitelist_function("argon2d_hash_raw")
        .whitelist_function("argon2id_hash_encoded")
        .whitelist_function("argon2id_hash_raw")
        .whitelist_function("argon2_hash")
        .whitelist_function("argon2i_verify")
        .whitelist_function("argon2d_verify")
        .whitelist_function("argon2id_verify")
        .whitelist_function("argon2_verify")
        .whitelist_function("argon2d_ctx")
        .whitelist_function("argon2i_ctx")
        .whitelist_function("argon2id_ctx")
        .whitelist_function("argon2d_verify_ctx")
        .whitelist_function("argon2i_verify_ctx")
        .whitelist_function("argon2id_verify_ctx")
        .whitelist_function("argon2_verify_ctx")
        .whitelist_function("argon2_error_message")
        .whitelist_function("argon2_encodedlen")
        .layout_tests(true)
        .generate()
        .expect("Failed to generate bindings.");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("argon2-bindings.rs"))
        .expect("Couldn't write bindings.");

    source_files.iter()
        .map(|p| p.to_str().expect("Failed to convert path to string."))
        .for_each(|f| println!("cargo:rerun-if-changed={}", f));
    println!("cargo:rerun-if-env-changed=CC");
}
