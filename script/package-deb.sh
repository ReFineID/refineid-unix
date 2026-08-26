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

# Build a binary Debian (.deb) package for ReFineID.
#
# The package includes:
#   - /usr/bin/refineid                  CLI binary
#   - /usr/bin/refineid-gui              Desktop GUI
#   - /usr/lib/librefineid_pkcs11.so     PKCS#11 module
#   - /usr/share/applications/refineid.desktop
#   - /usr/share/icons/hicolor/scalable/apps/refineid.svg
#   - /usr/share/p11-kit/modules/refineid.module
#   - /etc/firefox/policies/policies.json (automatic Firefox card login)
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

PKG_NAME="refineid_${VERSION}_${ARCH}"
DEB_DIR="target/deb"
STAGING_DIR="$DEB_DIR/$PKG_NAME"

rm -rf "$STAGING_DIR" "$DEB_DIR/${PKG_NAME}.deb"
mkdir -p \
    "$STAGING_DIR/DEBIAN" \
    "$STAGING_DIR/usr/bin" \
    "$STAGING_DIR/usr/lib" \
    "$STAGING_DIR/usr/share/applications" \
    "$STAGING_DIR/usr/share/icons/hicolor/scalable/apps" \
    "$STAGING_DIR/usr/share/p11-kit/modules" \
    "$STAGING_DIR/etc/firefox/policies"

# 1. Install binaries
install -m 755 target/release/refineid "$STAGING_DIR/usr/bin/refineid"
install -m 755 target/release/refineid-gui "$STAGING_DIR/usr/bin/refineid-gui"

# 2. Install PKCS#11 module
install -m 755 target/release/librefineid_pkcs11.so "$STAGING_DIR/usr/lib/librefineid_pkcs11.so"

# 3. Install desktop launcher and icon
cat > "$STAGING_DIR/usr/share/applications/refineid.desktop" << 'DESKTOPEOF'
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
chmod 644 "$STAGING_DIR/usr/share/applications/refineid.desktop"

install -m 644 crates/refineid-gui/assets/app-icon.svg \
    "$STAGING_DIR/usr/share/icons/hicolor/scalable/apps/refineid.svg"

# 4. Install p11-kit module registration
cat > "$STAGING_DIR/usr/share/p11-kit/modules/refineid.module" << 'P11EOF'
module: /usr/lib/librefineid_pkcs11.so
# Citizen client-auth keys, not CA trust anchors.
trust-policy: no
# A load failure must not take down every crypto consumer.
critical: no
P11EOF
chmod 644 "$STAGING_DIR/usr/share/p11-kit/modules/refineid.module"

# 5. Install Firefox enterprise policy for automatic card login
cat > "$STAGING_DIR/etc/firefox/policies/policies.json" << 'POLICIESEOF'
{
  "policies": {
    "SecurityDevices": {
      "ReFineID": "/usr/lib/librefineid_pkcs11.so"
    }
  }
}
POLICIESEOF
chmod 644 "$STAGING_DIR/etc/firefox/policies/policies.json"

# 6. Conffiles
cat > "$STAGING_DIR/DEBIAN/conffiles" << 'CONFFILESEOF'
/etc/firefox/policies/policies.json
CONFFILESEOF
chmod 644 "$STAGING_DIR/DEBIAN/conffiles"

# 7. Package control file
cat > "$STAGING_DIR/DEBIAN/control" << CONTROLEOF
Package: refineid
Version: ${VERSION}
Section: utils
Priority: optional
Architecture: ${ARCH}
Maintainer: Petri Koistinen <petri.koistinen@refineid.fi>
Depends: libc6, libpcsclite1, pcscd, libccid, p11-kit, libgtk-3-0, libfontconfig1, libx11-6, libxcursor1, libxi6, libxrandr2, libxkbcommon0
Recommends: pcsc-tools, firefox
Homepage: https://github.com/ReFineID/ReFineID-Unix
Description: Open-source FINEID middleware: CLI, PKCS#11 module, and desktop GUI
 ReFineID is an open-source FINEID smart-card middleware for Finnish identity
 cards on Linux. It provides the refineid command-line tool, a modern desktop
 GUI, and a PKCS#11 module enabling authentication, document signing, PIN
 management, and full card metadata inspection across browsers and crypto
 applications.
CONTROLEOF
chmod 644 "$STAGING_DIR/DEBIAN/control"

# 8. Post-installation script
cat > "$STAGING_DIR/DEBIAN/postinst" << 'POSTINSTEOF'
#!/bin/sh
set -e

case "$1" in
    configure)
        # Update dynamic linker bindings
        ldconfig

        # Update desktop application and icon caches
        if command -v update-desktop-database >/dev/null 2>&1; then
            update-desktop-database -q /usr/share/applications || true
        fi
        if command -v gtk-update-icon-cache >/dev/null 2>&1; then
            gtk-update-icon-cache -q -t -f /usr/share/icons/hicolor || true
        fi

        # Enable and activate the pcscd daemon socket if systemd is running
        if [ -d /run/systemd/system ]; then
            systemctl daemon-reload || true
            systemctl enable --now pcscd.socket || true
        fi
        ;;
    abort-upgrade|abort-remove|abort-deconfigure)
        ;;
    *)
        ;;
esac

exit 0
POSTINSTEOF
chmod 755 "$STAGING_DIR/DEBIAN/postinst"

# 9. Pre-removal script
cat > "$STAGING_DIR/DEBIAN/prerm" << 'PRERMEOF'
#!/bin/sh
set -e

case "$1" in
    remove|deconfigure)
        ;;
    upgrade|failed-upgrade)
        ;;
    *)
        ;;
esac

exit 0
PRERMEOF
chmod 755 "$STAGING_DIR/DEBIAN/prerm"

# 10. Post-removal script
cat > "$STAGING_DIR/DEBIAN/postrm" << 'POSTRMEOF'
#!/bin/sh
set -e

case "$1" in
    remove|purge)
        # Update dynamic linker bindings
        ldconfig

        # Refresh desktop application and icon caches
        if command -v update-desktop-database >/dev/null 2>&1; then
            update-desktop-database -q /usr/share/applications || true
        fi
        if command -v gtk-update-icon-cache >/dev/null 2>&1; then
            gtk-update-icon-cache -q -t -f /usr/share/icons/hicolor || true
        fi
        ;;
    upgrade|failed-upgrade|abort-install|abort-upgrade|disappear)
        ;;
    *)
        ;;
esac

exit 0
POSTRMEOF
chmod 755 "$STAGING_DIR/DEBIAN/postrm"

echo "Packing Debian package..."
dpkg-deb --build --root-owner-group "$STAGING_DIR" "$DEB_DIR/${PKG_NAME}.deb"
rm -rf "$STAGING_DIR"

echo "Successfully built package: $DEB_DIR/${PKG_NAME}.deb"
