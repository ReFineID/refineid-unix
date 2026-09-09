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

//! `reader keyboard` typed arguments.

use crate::reader_keyboard::KeyboardAction;

use super::{ArgParseError, argv::RemainingArgv, verb::VerbTag};

/// Parsed `reader keyboard [off|on] [--reader SUBSTR]` arguments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReaderKeyboardArgs {
    /// What to do: bare `keyboard` reports, `off` / `on` set.
    pub action: KeyboardAction,
    /// Optional reader-name substring (`--reader SUBSTR`).
    pub reader_filter: Option<String>,
}

impl ReaderKeyboardArgs {
    /// Parse the remaining argv after `reader keyboard`.
    ///
    /// # Errors
    /// Unknown token or a `--reader` with no value.
    pub fn parse(argv: RemainingArgv) -> Result<Self, ArgParseError> {
        let mut action = KeyboardAction::Status;
        let mut reader_filter = None;
        let mut it = argv.into_vec().into_iter();
        while let Some(token) = it.next() {
            match token.as_str() {
                "off" => action = KeyboardAction::Off,
                "on" => action = KeyboardAction::On,
                "status" => action = KeyboardAction::Status,
                "--reader" => {
                    let Some(value) = it.next() else {
                        return Err(ArgParseError::MissingValue {
                            cmd: VerbTag::ReaderKeyboard,
                            flag: "--reader",
                        });
                    };
                    reader_filter = Some(value);
                }
                _other => {
                    return Err(ArgParseError::Unexpected {
                        cmd: VerbTag::ReaderKeyboard,
                        got: token,
                    });
                }
            }
        }
        Ok(Self {
            action,
            reader_filter,
        })
    }

    /// Execute the `reader keyboard` verb.
    #[must_use]
    pub fn run(self) -> std::process::ExitCode {
        match crate::reader_keyboard::run(self.action, self.reader_filter.as_deref()) {
            Ok(lines) => {
                for line in &lines {
                    println!("{line}");
                }
                crate::exit_status::ExitStatus::Ok.into()
            }
            Err(crate::reader_keyboard::KeyboardError::NoReaders) => {
                eprintln!("no PC/SC readers connected");
                crate::exit_status::ExitStatus::NoReaders.into()
            }
            Err(e) => {
                eprintln!("reader keyboard: {e}");
                crate::exit_status::ExitStatus::RuntimeFailure.into()
            }
        }
    }
}
