# Installing RefineID on NetBSD

Verified on NetBSD 11.0/aarch64 (evbarm) under VMware Fusion, September 2026.
The whole workspace builds there, including the Slint GUI. What follows is
the exact bring-up order; every NetBSD-specific step exists because the
default install lacks it.

## 1. Base X sets

A default install ships no X11 (`/usr/X11R7` absent), and pkgsrc packages
such as `dbus` link against base X libraries, so install the sets first:

```sh
cd /
for s in xbase xcomp xetc xfont; do
  ftp -o /tmp/$s.tar.xz \
    https://cdn.NetBSD.org/pub/NetBSD/NetBSD-11.0/evbarm-aarch64/binary/sets/$s.tar.xz
  tar -xJpf /tmp/$s.tar.xz
  rm -f /tmp/$s.tar.xz
done
```

Adjust the `evbarm-aarch64` path component for other ports.

## 2. Toolchain and libraries from pkgsrc

```sh
export PATH=/usr/pkg/bin:$PATH
pkgin update
pkgin -y install rust-bin mozilla-rootcerts git pkg-config \
  pcsc-lite ccid pcsc-tools fontconfig dbus gtk3+ xkbcommon wayland
```

Notes:

- pkgsrc ships Rust 1.96.0, one minor below the workspace MSRV (1.97).
  Everything still compiles; pass `--ignore-rust-version` to cargo.
  No 1.97-only language or library feature is actually used.
- `gtk3+`, `xkbcommon`, and `wayland` are build requirements of the GUI
  stack only (`rfd`, `winit`); the CLI and PKCS#11 module do not need them.
- On memory-small VMs, cap cargo parallelism (`-j4` on 4 vCPUs); an
  uncapped Slint release build wedged a 4-CPU guest hard enough that sshd
  stopped answering.

## 3. Build

```sh
export PKG_CONFIG_PATH=/usr/pkg/lib/pkgconfig:/usr/X11R7/lib/pkgconfig
cargo build --release --workspace --ignore-rust-version -j4
```

pkgsrc libraries live outside the default loader path and NetBSD has no
`ldconfig` for them, so GUI binaries that link pkgsrc libraries (GTK3 via
`rfd`) need the path baked in at link time, otherwise they fail at startup
with `Shared object "libgtk-3.so.0" not found`:

```sh
RUSTFLAGS="-C link-args=-Wl,-R/usr/pkg/lib" \
  cargo build --release -p refineid-gui --ignore-rust-version
```

## 4. Smart-card daemon

The in-tree `ccid` bundle lives under `/usr/pkg/lib/pcsc-lite/drivers`,
which is also pcscd's compiled-in driver directory, so no configuration
is needed:

```sh
/usr/pkg/sbin/pcscd
timeout 8 pcsc_scan
```

A passed-through USB reader appears as `ugen` (e.g. `ugen0: ... EMV
Smartcard Reader`) and `pcsc_scan` lists it with card state and ATR.
In VMware, attach the reader via the VM's USB menu; while attached there
the macOS host no longer sees it.

## 5. Desktop integration

`script/install-desktop.sh` installs the GUI binary, the freedesktop
launcher (`packaging/refineid.desktop`, shared with the .deb packaging),
and the icon, then refreshes the caches:

```sh
script/install-desktop.sh --prefix /usr/local
```

With `--openbox-menu` it additionally files a "RefineID" item under
Applications/Accessories. Openbox ships a fully static example menu, so
the script copies the system `menu.xml` to `~/.config/openbox/menu.xml`
(a user override; package files stay untouched), appends the item, and
reconfigures a running Openbox when `DISPLAY` is set:

```sh
script/install-desktop.sh --prefix /usr/local --openbox-menu
```

### System fonts on NetBSD

Font discovery on NetBSD finds no families through Slint's font stack
(fontique), so the GUI aborts in font fallback (`query_fontique().unwrap()`
on `None`). Point it at the base system fonts:

```sh
export SLINT_DEFAULT_FONT=/usr/X11R7/lib/X11/fonts/TTF/LiberationSans-Regular.ttf
export SLINT_FONT_PATH=/usr/X11R7/lib/X11/fonts/TTF
```

`script/install-desktop.sh` bakes these into the installed launcher and
the Openbox menu item automatically when the paths exist.

## 6. Headless desktop over VNC (optional)

Mac Screen Sharing speaks plain VNC. On NetBSD:

```sh
pkgin -y install tigervnc openbox
mkdir -p ~/.vnc
vncpasswd -f > ~/.vnc/passwd   # type the password on a tty; chmod 600 it
Xvnc :1 -geometry 1920x1080 -depth 24 \
  -rfbauth ~/.vnc/passwd -rfbport 5901 -SecurityTypes VNCAuth &
DISPLAY=:1 openbox &
DISPLAY=:1 xterm &
```

(TigerVNC's `vncserver` wrapper insists on an interactive password prompt;
starting `Xvnc` directly avoids it.) Then Finder -> Cmd+K ->
`vnc://<guest>:5901`. Unencrypted RFB: LAN only, otherwise tunnel with
`ssh -L 5901:localhost:5901`.

## 7. Firefox (optional)

`pkgin -y install firefox140` gives a working ESR build; verified with a
headless `--screenshot` render. This is the counterpart for testing the
PKCS#11 module (`librefineid_pkcs11.so`) against real NSS discovery.

## Known limits

- Compile-checked and smoke-run only: the GUI binary builds and starts
  under Xvnc, but no interactive session testing has been done.
- No OpenBSD target ships in the used toolchain; this page covers NetBSD.
- `RUSTSEC` unmaintained-crate warnings in the Slint dependency cone
  (bincode, paste, rustybuzz, ttf-parser) are GUI-only transitives and
  unaffected by the platform port.
