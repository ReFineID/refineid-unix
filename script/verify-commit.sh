#!/bin/sh
# Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.
set -eu

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

if ! command -v cargo >/dev/null 2>&1; then
    echo "verify-commit: cargo not found on PATH" >&2
    exit 1
fi

cargo fmt --all --check
cargo check --workspace --all-targets
echo "pre-commit quality gates passed."
