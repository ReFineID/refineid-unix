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

# Point this repository's git hooks at script/githook/.
#
# Usage:
#   script/install-githook.sh            # install
#   script/install-githook.sh --check    # verify only

set -eu

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
HOOK_DIR="script/githook"

check_only=0
case "${1:-}" in
    -c|--check) check_only=1 ;;
    -h|--help) sed -n '18,21p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    "") ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
esac

[ -f "$REPO_ROOT/$HOOK_DIR/pre-commit" ] || {
    echo "missing canonical hook: $REPO_ROOT/$HOOK_DIR/pre-commit" >&2
    exit 1
}
[ -f "$REPO_ROOT/$HOOK_DIR/pre-push" ] || {
    echo "missing canonical hook: $REPO_ROOT/$HOOK_DIR/pre-push" >&2
    exit 1
}

if [ "$check_only" -eq 1 ]; then
    hp=$(git -C "$REPO_ROOT" config --get core.hooksPath 2>/dev/null || true)
    if [ "$hp" != "$HOOK_DIR" ]; then
        echo "verify: core.hooksPath is '$hp' (expected: $HOOK_DIR)" >&2
        echo "  run install-githook.sh to fix." >&2
        exit 1
    fi
    echo "verify: core.hooksPath = $HOOK_DIR, hooks present. OK."
    exit 0
fi

chmod +x "$REPO_ROOT/$HOOK_DIR/pre-commit" "$REPO_ROOT/$HOOK_DIR/pre-push"
git -C "$REPO_ROOT" config core.hooksPath "$HOOK_DIR"
echo "githooks installed: core.hooksPath = $HOOK_DIR"
