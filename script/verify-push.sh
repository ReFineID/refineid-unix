#!/bin/sh
# Copyright 2026 Petri Koistinen. Licensed under the Apache License, Version 2.0.
set -eu

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

if ! command -v cargo >/dev/null 2>&1; then
    echo "verify-push: cargo not found on PATH" >&2
    exit 1
fi

echo "== verify-push: format check =="
cargo fmt --all --check

echo "== verify-push: workspace build =="
cargo build --workspace --all-targets

echo "== verify-push: unit tests =="
cargo test --workspace

echo "== verify-push: clippy =="
cargo clippy --workspace --all-targets -- -D warnings

echo "== verify-push: rustdoc =="
cargo doc --workspace --no-deps

echo "pre-push full floor passed."
