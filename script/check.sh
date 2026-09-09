#!/bin/sh
# Copyright 2026 Petri Koistinen
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied. See the License for the specific language governing
# permissions and limitations under the License.

# Local strict-build verification: build / test (incl. doctests) /
# clippy -D warnings / fmt. Run before pushing.
#
# Usage:
#   script/check.sh

set -eu

cd "$(dirname "$0")/.."

run() {
    printf '\n== %s ==\n' "$*" >&2
    "$@" || { echo "FAIL: $*" >&2; exit 1; }
}

run cargo build --workspace --all-targets
run cargo test --workspace
run cargo clippy --workspace --all-targets -- -D warnings
run cargo fmt --all --check

printf '\nall gates green.\n' >&2
