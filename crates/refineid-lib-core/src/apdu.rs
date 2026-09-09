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

//! Shared APDU primitives.
//!
//! This module hosts the small set of types that every protocol
//! module needs when constructing or parsing ISO 7816-4 APDUs:
//! status words, class / instruction bytes, application
//! identifiers, short-file identifiers, and similar low-level
//! shapes.
//!
//! Protocol-specific APDU command structs (e.g. PACE's
//! `GeneralAuthenticate`, signature's `ComputeDigitalSignature`,
//! PKCS#15's `SelectFile` / `ReadBinary`) live next to their
//! drivers in those protocol modules (`pace::commands`,
//! `sign::commands`, `pkcs15::commands`). Each protocol owns its
//! own APDU shapes so a future re-shuffle of, say, the PACE
//! driver can take its APDUs with it.
//!
//! See `doc/typing-discipline.md` for the API-discipline rules
//! that motivate this split (no untyped bytes across the card
//! boundary; every byte sequence has a protocol role and a
//! typed container).

pub mod iso7816;
pub mod primitives;
pub mod status_word;
