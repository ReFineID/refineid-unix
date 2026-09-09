// Copyright 2026 Petri Koistinen
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied. See the License for the specific language governing
// permissions and limitations under the License.

//! Build the Slint component definitions for the Card Manager binary.

fn main() {
    println!("cargo:rerun-if-env-changed=REFINEID_GUI_BUILD_VERSION_OVERRIDE");
    let version = std::env::var("REFINEID_GUI_BUILD_VERSION_OVERRIDE")
        .unwrap_or_else(|_| env!("REFINEID_VERSION").to_owned());
    println!("cargo:rustc-env=REFINEID_GUI_BUILD_VERSION={version}");
    slint_build::compile("ui/refineid-gui.slint").expect("compile ReFineID GUI");
}
