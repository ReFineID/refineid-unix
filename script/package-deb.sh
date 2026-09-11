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

# Build binary Debian (.deb) packages for ReFineID.
#
# Packages generated:
#   1. refineid-pkcs11: PKCS#11 module, p11-kit configuration, Firefox enterprise policy
#   2. refineid-cli:    Command-line tool (/usr/bin/refineid)
#   3. refineid-gui:    Desktop GUI tool (/usr/bin/refineid-gui), launcher, icons
#   4. refineid:        Metapackage pulling in CLI, PKCS#11, and GUI
#
# Usage: script/package-deb.sh

set -eu
cd "$(dirname "$0")/.."

if ! command -v dpkg-deb >/dev/null 2>&1; then
    echo "error: dpkg-deb not found. Please install dpkg (sudo apt install dpkg)" >&2
    exit 1
fi

VERSION="$(tr -d '\r\n ' < VERSION)"
if [ -z "$VERSION" ]; then
    echo "error: VERSION file is empty" >&2
    exit 1
fi

ARCH="$(dpkg --print-architecture 2>/dev/null || uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')"

echo "Building release binaries with cargo..."
cargo build --release --workspace

DEB_DIR="target/deb"
mkdir -p "$DEB_DIR"

# ==============================================================================
# Package 1: refineid-pkcs11
# ==============================================================================
PKG_PKCS11="refineid-pkcs11_${VERSION}_${ARCH}"
STAGING_PKCS11="$DEB_DIR/$PKG_PKCS11"
echo "Packaging $PKG_PKCS11..."
rm -rf "$STAGING_PKCS11" "$DEB_DIR/${PKG_PKCS11}.deb"
mkdir -p \
    "$STAGING_PKCS11/DEBIAN" \
    "$STAGING_PKCS11/usr/lib" \
    "$STAGING_PKCS11/usr/share/p11-kit/modules" \
    "$STAGING_PKCS11/etc/firefox/policies"

install -m 755 target/release/librefineid_pkcs11.so "$STAGING_PKCS11/usr/lib/librefineid_pkcs11.so"

cat > "$STAGING_PKCS11/usr/share/p11-kit/modules/refineid.module" << 'P11EOF'
module: /usr/lib/librefineid_pkcs11.so
trust-policy: no
critical: no
P11EOF
chmod 644 "$STAGING_PKCS11/usr/share/p11-kit/modules/refineid.module"

cat > "$STAGING_PKCS11/etc/firefox/policies/policies.json" << 'POLICIESEOF'
{
  "policies": {
    "SecurityDevices": {
      "ReFineID": "/usr/lib/librefineid_pkcs11.so"
    }
  }
}
POLICIESEOF
chmod 644 "$STAGING_PKCS11/etc/firefox/policies/policies.json"

cat > "$STAGING_PKCS11/DEBIAN/conffiles" << 'CONFFILESEOF'
/etc/firefox/policies/policies.json
CONFFILESEOF
chmod 644 "$STAGING_PKCS11/DEBIAN/conffiles"

cat > "$STAGING_PKCS11/DEBIAN/control" << CONTROLEOF
Package: refineid-pkcs11
Version: ${VERSION}
Section: utils
Priority: optional
Architecture: ${ARCH}
Maintainer: Petri Koistinen <petri.koistinen@refineid.fi>
Depends: libc6, libpcsclite1, p11-kit
Recommends: pcscd, libccid
Homepage: https://github.com/refineid/refineid-unix
Description: Open-source FINEID PKCS#11 module for Finnish identity cards
 ReFineID PKCS#11 module enabling authentication, document signing, and
 card cryptography across web browsers (Firefox, Chrome), OpenSC, and
 NSS applications.
CONTROLEOF
chmod 644 "$STAGING_PKCS11/DEBIAN/control"

cat > "$STAGING_PKCS11/DEBIAN/postinst" << 'POSTINSTEOF'
#!/bin/sh
set -e
if [ "$1" = "configure" ]; then
    ldconfig
fi
exit 0
POSTINSTEOF
chmod 755 "$STAGING_PKCS11/DEBIAN/postinst"

cat > "$STAGING_PKCS11/DEBIAN/postrm" << 'POSTRMEOF'
#!/bin/sh
set -e
if [ "$1" = "remove" ] || [ "$1" = "purge" ]; then
    ldconfig
fi
exit 0
POSTRMEOF
chmod 755 "$STAGING_PKCS11/DEBIAN/postrm"

dpkg-deb --build --root-owner-group "$STAGING_PKCS11" "$DEB_DIR/${PKG_PKCS11}.deb"
rm -rf "$STAGING_PKCS11"

# ==============================================================================
# Package 2: refineid-cli
# ==============================================================================
PKG_CLI="refineid-cli_${VERSION}_${ARCH}"
STAGING_CLI="$DEB_DIR/$PKG_CLI"
echo "Packaging $PKG_CLI..."
rm -rf "$STAGING_CLI" "$DEB_DIR/${PKG_CLI}.deb"
mkdir -p \
    "$STAGING_CLI/DEBIAN" \
    "$STAGING_CLI/usr/bin"

install -m 755 target/release/refineid "$STAGING_CLI/usr/bin/refineid"

cat > "$STAGING_CLI/DEBIAN/control" << CONTROLEOF
Package: refineid-cli
Version: ${VERSION}
Section: utils
Priority: optional
Architecture: ${ARCH}
Maintainer: Petri Koistinen <petri.koistinen@refineid.fi>
Depends: libc6, libpcsclite1
Recommends: pcscd, libccid, refineid-pkcs11
Homepage: https://github.com/refineid/refineid-unix
Description: Open-source FINEID command-line tool for Finnish identity cards
 ReFineID command-line interface for smart card status inspection, PIN verification
 and change, remote card pairing (RAPP), and authentication testing.
CONTROLEOF
chmod 644 "$STAGING_CLI/DEBIAN/control"

dpkg-deb --build --root-owner-group "$STAGING_CLI" "$DEB_DIR/${PKG_CLI}.deb"
rm -rf "$STAGING_CLI"

# ==============================================================================
# Package 3: refineid-gui
# ==============================================================================
PKG_GUI="refineid-gui_${VERSION}_${ARCH}"
STAGING_GUI="$DEB_DIR/$PKG_GUI"
echo "Packaging $PKG_GUI..."
rm -rf "$STAGING_GUI" "$DEB_DIR/${PKG_GUI}.deb"
mkdir -p \
    "$STAGING_GUI/DEBIAN" \
    "$STAGING_GUI/usr/bin" \
    "$STAGING_GUI/usr/share/applications" \
    "$STAGING_GUI/usr/share/icons/hicolor/scalable/apps"

install -m 755 target/release/refineid-gui "$STAGING_GUI/usr/bin/refineid-gui"

cat > "$STAGING_GUI/usr/share/applications/refineid.desktop" << 'DESKTOPEOF'
[Desktop Entry]
Type=Application
Name=ReFineID
GenericName=Identity card tool
Comment=Finnish identity card: PIN management, portrait and signature, document signing
Exec=refineid-gui
Icon=refineid
Terminal=false
Categories=Utility;Security;
Keywords=FINEID;smartcard;PIN;identity;signing;
DESKTOPEOF
chmod 644 "$STAGING_GUI/usr/share/applications/refineid.desktop"

install -m 644 crates/refineid-gui/assets/app-icon.svg \
    "$STAGING_GUI/usr/share/icons/hicolor/scalable/apps/refineid.svg"

cat > "$STAGING_GUI/DEBIAN/control" << CONTROLEOF
Package: refineid-gui
Version: ${VERSION}
Section: utils
Priority: optional
Architecture: ${ARCH}
Maintainer: Petri Koistinen <petri.koistinen@refineid.fi>
Depends: libc6, libpcsclite1, libgtk-3-0 | libgtk-3-0t64, libfontconfig1, libx11-6, libxcursor1, libxi6, libxrandr2, libxkbcommon0, refineid-cli (= ${VERSION})
Recommends: refineid-pkcs11 (= ${VERSION})
Homepage: https://github.com/refineid/refineid-unix
Description: Graphical user interface for Finnish identity cards
 ReFineID graphical desktop application for PIN management, card portrait and
 signature inspection, document signing, and pairing management.
CONTROLEOF
chmod 644 "$STAGING_GUI/DEBIAN/control"

cat > "$STAGING_GUI/DEBIAN/postinst" << 'POSTINSTEOF'
#!/bin/sh
set -e
if [ "$1" = "configure" ]; then
    if command -v update-desktop-database >/dev/null 2>&1; then
        update-desktop-database -q /usr/share/applications || true
    fi
    if command -v gtk-update-icon-cache >/dev/null 2>&1; then
        gtk-update-icon-cache -q -t -f /usr/share/icons/hicolor || true
    fi
fi
exit 0
POSTINSTEOF
chmod 755 "$STAGING_GUI/DEBIAN/postinst"

cat > "$STAGING_GUI/DEBIAN/postrm" << 'POSTRMEOF'
#!/bin/sh
set -e
if [ "$1" = "remove" ] || [ "$1" = "purge" ]; then
    if command -v update-desktop-database >/dev/null 2>&1; then
        update-desktop-database -q /usr/share/applications || true
    fi
    if command -v gtk-update-icon-cache >/dev/null 2>&1; then
        gtk-update-icon-cache -q -t -f /usr/share/icons/hicolor || true
    fi
fi
exit 0
POSTRMEOF
chmod 755 "$STAGING_GUI/DEBIAN/postrm"

dpkg-deb --build --root-owner-group "$STAGING_GUI" "$DEB_DIR/${PKG_GUI}.deb"
rm -rf "$STAGING_GUI"

# ==============================================================================
# Package 4: refineid (Metapackage)
# ==============================================================================
PKG_META="refineid_${VERSION}_${ARCH}"
STAGING_META="$DEB_DIR/$PKG_META"
echo "Packaging $PKG_META (metapackage)..."
rm -rf "$STAGING_META" "$DEB_DIR/${PKG_META}.deb"
mkdir -p "$STAGING_META/DEBIAN"

cat > "$STAGING_META/DEBIAN/control" << CONTROLEOF
Package: refineid
Version: ${VERSION}
Section: utils
Priority: optional
Architecture: ${ARCH}
Maintainer: Petri Koistinen <petri.koistinen@refineid.fi>
Depends: refineid-cli (>= ${VERSION}), refineid-pkcs11 (>= ${VERSION}), refineid-gui (>= ${VERSION})
Recommends: pcscd, libccid, pcsc-tools
Homepage: https://github.com/refineid/refineid-unix
Description: Open-source FINEID middleware for Finnish identity cards (metapackage)
 ReFineID is an open-source FINEID smart-card middleware for Finnish identity
 cards on Linux. This metapackage installs the command-line tool, PKCS#11 module,
 and desktop GUI.
CONTROLEOF
chmod 644 "$STAGING_META/DEBIAN/control"

cat > "$STAGING_META/DEBIAN/postinst" << 'POSTINSTEOF'
#!/bin/sh
set -e
if [ "$1" = "configure" ]; then
    if [ -d /run/systemd/system ]; then
        systemctl daemon-reload || true
        systemctl enable --now pcscd.socket || true
    fi
fi
exit 0
POSTINSTEOF
chmod 755 "$STAGING_META/DEBIAN/postinst"

dpkg-deb --build --root-owner-group "$STAGING_META" "$DEB_DIR/${PKG_META}.deb"
rm -rf "$STAGING_META"

echo "Successfully built Debian packages in $DEB_DIR:"
ls -lh "$DEB_DIR"/*.deb
