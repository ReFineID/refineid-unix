// Copyright 2026 Petri Koistinen
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

//! Generate the PKCS#11 token version from the canonical release version.

use std::env;
use std::fs;
use std::path::PathBuf;

fn main() {
    let manifest = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("manifest path"));
    let version_path = manifest.join("../../VERSION");
    println!("cargo:rerun-if-changed={}", version_path.display());

    let version = fs::read_to_string(version_path).expect("read VERSION");
    let parts: Vec<u8> = version
        .trim()
        .split('.')
        .map(|part| part.parse().expect("numeric VERSION component"))
        .collect();
    assert_eq!(parts.len(), 4, "VERSION must be YY.M.D.B");

    let out = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR"));
    let source = format!(
        "const TOKEN_FIRMWARE_VERSION: CkVersion = CkVersion {{ major: {}, minor: {} }};\n",
        parts[2], parts[3]
    );
    fs::write(out.join("token-version.rs"), source).expect("write token version");
}
