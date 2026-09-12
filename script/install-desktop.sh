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
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Install the RefineID desktop GUI outside of .deb packaging:
# binary, freedesktop launcher, and icon.
#
# Usage:
#   script/install-desktop.sh [--prefix /usr/local] [--openbox-menu]
#
# --openbox-menu also adds a "RefineID" item under Applications/Accessories
# in Openbox. Openbox ships a fully static example menu, so this creates a
# user-level override at ~/.config/openbox/menu.xml (package files are left
# untouched) and reconfigures a running Openbox when DISPLAY is set.
#
# Environment:
#   BIN      path to the built GUI binary (default: target/release/refineid-gui)
#   DESTDIR  staging root, empty for a live install

set -eu

cd "$(dirname "$0")/.."

PREFIX="/usr/local"
OPENBOX_MENU=0

while [ $# -gt 0 ]; do
    case "$1" in
        --prefix) PREFIX="$2"; shift 2 ;;
        --openbox-menu) OPENBOX_MENU=1; shift ;;
        *) echo "usage: $0 [--prefix DIR] [--openbox-menu]" >&2; exit 2 ;;
    esac
done

BIN="${BIN:-target/release/refineid-gui}"
DESTDIR="${DESTDIR:-}"

if [ ! -x "$BIN" ]; then
    echo "error: GUI binary not found or not executable: $BIN" >&2
    echo "build it first: cargo build --release -p refineid-gui" >&2
    exit 1
fi

install -d \
    "$DESTDIR$PREFIX/bin" \
    "$DESTDIR$PREFIX/share/applications" \
    "$DESTDIR$PREFIX/share/icons/hicolor/scalable/apps"

install -m 755 "$BIN" "$DESTDIR$PREFIX/bin/refineid-gui"
install -m 644 packaging/refineid.desktop \
    "$DESTDIR$PREFIX/share/applications/refineid.desktop"
install -m 644 crates/refineid-gui/assets/app-icon.svg \
    "$DESTDIR$PREFIX/share/icons/hicolor/scalable/apps/refineid.svg"

# Slint's font stack (fontique) finds no system fonts on NetBSD, so the GUI
# aborts in font fallback unless told where a default font lives. When the
# NetBSD base fonts are present, wrap the launch command accordingly; the
# variables are ignored anywhere else, and a missing file is skipped, so
# this is a no-op on systems with working font discovery.
GUI_EXEC="$DESTDIR$PREFIX/bin/refineid-gui"
if [ -f /usr/X11R7/lib/X11/fonts/TTF/LiberationSans-Regular.ttf ]; then
    GUI_EXEC="env SLINT_DEFAULT_FONT=/usr/X11R7/lib/X11/fonts/TTF/LiberationSans-Regular.ttf SLINT_FONT_PATH=/usr/X11R7/lib/X11/fonts/TTF $GUI_EXEC"
    if [ -z "$DESTDIR" ]; then
        sed "s|^Exec=.*|Exec=$GUI_EXEC|" \
            "$DESTDIR$PREFIX/share/applications/refineid.desktop" \
            > "$DESTDIR$PREFIX/share/applications/refineid.desktop.new" \
            && mv "$DESTDIR$PREFIX/share/applications/refineid.desktop.new" \
                   "$DESTDIR$PREFIX/share/applications/refineid.desktop"
    fi
fi

if [ -z "$DESTDIR" ]; then
    if command -v update-desktop-database >/dev/null 2>&1; then
        update-desktop-database -q "$PREFIX/share/applications" || true
    fi
    if command -v gtk-update-icon-cache >/dev/null 2>&1; then
        gtk-update-icon-cache -q -t -f "$PREFIX/share/icons/hicolor" || true
    fi
fi

if [ "$OPENBOX_MENU" -eq 1 ]; then
    MENU_HOME="${HOME:-/root}/.config/openbox/menu.xml"
    if [ ! -f "$MENU_HOME" ]; then
        SRC=""
        for d in "$PREFIX/etc/xdg/openbox" /usr/pkg/etc/xdg/openbox \
                 /etc/xdg/openbox /usr/local/etc/xdg/openbox; do
            if [ -f "$d/menu.xml" ]; then SRC="$d/menu.xml"; break; fi
        done
        if [ -z "$SRC" ]; then
            echo "error: no system openbox menu.xml found" >&2
            exit 1
        fi
        install -d "$(dirname "$MENU_HOME")"
        cp "$SRC" "$MENU_HOME"
    fi
    if grep -q 'label="RefineID"' "$MENU_HOME"; then
        sed "/label=\"RefineID\"/,/<\/item>/ s|<command>.*</command>|<command>$GUI_EXEC</command>|" \
            "$MENU_HOME" > "$MENU_HOME.new" \
            && mv "$MENU_HOME.new" "$MENU_HOME"
        echo "menu: RefineID command refreshed in $MENU_HOME"
    else
        awk '/^<\/menu>$/ && !done {
                 print "  <item label=\"RefineID\">"
                 print "    <action name=\"Execute\">"
                 print "      <command>'"$GUI_EXEC"'</command>"
                 print "      <startupnotify>"
                 print "        <enabled>yes</enabled>"
                 print "      </startupnotify>"
                 print "    </action>"
                 print "  </item>"
                 done=1
             } {print}' "$MENU_HOME" > "$MENU_HOME.new" \
            && mv "$MENU_HOME.new" "$MENU_HOME"
        echo "menu: RefineID added under Accessories in $MENU_HOME"
    fi
    if [ -n "${DISPLAY:-}" ] && command -v openbox >/dev/null 2>&1; then
        openbox --reconfigure 2>/dev/null || true
    else
        echo "menu: set DISPLAY and run 'openbox --reconfigure' to reload"
    fi
fi

echo "installed refineid-gui to $DESTDIR$PREFIX/bin/refineid-gui"
