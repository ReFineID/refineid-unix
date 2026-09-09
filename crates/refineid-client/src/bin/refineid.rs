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

//! `refineid` -- main CLI entry point.
//!
//! Subcommands fall into four groups:
//!
//! - **Card readout** (no PIN required): bare `refineid card`
//!   walks every FINEID-responding reader and produces a full
//!   per-card report (identity, cert chain with revocation,
//!   PIN counters, optionally the eMRTD layer when a CAN is
//!   supplied). `card pubkey` and `card emrtd` are the
//!   read-only sibling tools for SSH-format pubkey extraction
//!   and eMRTD file dumps.
//! - **PIN-gated crypto**: `card sign-auth`,
//!   `card sign-qualified`, `card decrypt-auth`.
//! - **PIN management** (rotate / unblock / first-time
//!   activation): `card activate`, `card change-pin1`,
//!   `card change-pin2`, `card unblock-pin1`,
//!   `card unblock-pin2`.
//! - **Offline tools** (no card / no network): `verify`,
//!   `cert show`, `cert chain`.
//!
//! Run `refineid --help` for the full usage block with per-
//! subcommand flags.
//!
//! All of the work lives in the library:
//! [`refineid_client::cli::read_command_line`] parses argv into
//! a typed [`refineid_client::cli::Verb`], and `Verb::run`
//! dispatches to the appropriate handler. This file is just the
//! entry point.

#![forbid(unsafe_code)]
// CLI-output lint carve-outs for the bin target. Same shape and
// rationale as `refineid-client/src/lib.rs` (CLI is the primary
// output surface; the structured-event system covers observations
// per `doc/observability.md`).

use std::process::ExitCode;

use refineid_lib_core::events::{StderrSink, set_global_sink};

fn main() -> ExitCode {
    // Install the structured-event sink before any code can emit
    // an event. Per Rule E17 (no call home in the personal
    // profile), only the stderr sink is enabled by default;
    // future deployment profiles add OS-managed / forensic sinks
    // via `--log-sink=` flags. SinkAlreadySet cannot occur here
    // because main() is the only call site; the Result is
    // bound with an explicit type and discarded.
    let _install_result: Result<(), refineid_lib_core::events::SinkAlreadySet> =
        set_global_sink(Box::new(StderrSink::new()));

    match refineid_client::cli::read_command_line() {
        Ok(verb) => verb.run(),
        Err(exit) => exit,
    }
}
