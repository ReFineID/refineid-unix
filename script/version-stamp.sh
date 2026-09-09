#!/usr/bin/env bash
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

# Stamp the project version across the tree. The canonical version is
# CalVer YY.M.D.B, where B is a within-day 10-minute bucket
# (hour*10 + minute/10, 0..235). Updates:
#   VERSION                 canonical four-component string
#   .cargo/config.toml      REFINEID_VERSION (compiled into binaries)
#   Cargo.toml              workspace three-component SemVer projection
#
# Usage: script/version-stamp.sh

set -eu
cd "$(dirname "$0")/.."

read -r year month day hour minute < <(date '+%y %-m %-d %-H %-M')
today="$year.$month.$day"
time_bucket=$((10#$hour * 10 + 10#$minute / 10))
project_version="$today.$time_bucket"
old=$(sed -n 's/^version = "\([0-9.]*\)"$/\1/p' Cargo.toml | head -n 1)
[ -n "$old" ] || { echo "version-stamp: no workspace version" >&2; exit 1; }
old_project=$(tr -d '\n' < VERSION)

old_ifs=$IFS
IFS=.
set -- $today
IFS=$old_ifs
[ "$#" -eq 3 ] || { echo "version-stamp: invalid date stamp $today" >&2; exit 1; }
for component in "$@"; do
    case "$component" in
        ''|*[!0-9]*) echo "version-stamp: non-numeric component $component" >&2; exit 1 ;;
    esac
    [ "$component" -le 255 ] || {
        echo "version-stamp: component $component exceeds PKCS#11 byte range" >&2
        exit 1
    }
done
[ "$time_bucket" -le 255 ] || {
    echo "version-stamp: time bucket $time_bucket exceeds PKCS#11 byte range" >&2
    exit 1
}

printf '%s\n' "$project_version" > VERSION

awk -v version="$project_version" '
    /^REFINEID_VERSION = / {
        sub(/value = "[0-9.]+"/, "value = \"" version "\"")
    }
    { print }
' .cargo/config.toml > .cargo/config.toml.tmp.$$ \
    && mv .cargo/config.toml.tmp.$$ .cargo/config.toml

if [ "$old" != "$today" ]; then
awk -v version="$today" '
    /^version = "/ && !done { sub(/"[^"]*"/, "\"" version "\""); done=1 }
    { print }
' Cargo.toml > Cargo.toml.tmp.$$ && mv Cargo.toml.tmp.$$ Cargo.toml

awk -v old="$old" -v version="$today" '
    function flush_package(    i, line) {
        for (i = 0; i < count; i++) {
            line = lines[i]
            if (!has_source && line == "version = \"" old "\"") {
                line = "version = \"" version "\""
            }
            print line
        }
        in_package=0; count=0; has_source=0
    }
    /^\[\[package\]\]/ { in_package=1; count=0; has_source=0 }
    in_package {
        lines[count++] = $0
        if ($0 ~ /^source = /) has_source=1
        if ($0 == "") flush_package()
        next
    }
    { print }
    END { if (in_package) flush_package() }
' Cargo.lock > Cargo.lock.tmp.$$ && mv Cargo.lock.tmp.$$ Cargo.lock

fi

printf 'version-stamp: %s -> %s (workspace %s)\n' "$old_project" "$project_version" "$today"
