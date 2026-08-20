# Installing ReFineID on NixOS

Everything below builds ReFineID from this source tree. Nix fetches
every build dependency (Rust toolchain, pcsc-lite, fontconfig, GUI
libraries) by itself; nothing needs to be installed by hand first.

Building needs a few gigabytes of memory free; on a small machine or
VM, add swap before building -- see Troubleshooting. Only the first
build compiles everything: the dependency build is kept in the local
Nix store and reused, so following the repository rebuilds just the
ReFineID crates.

## Fresh machine, shortest path (not recommended)

Add to `/etc/nixos/configuration.nix`:

```nix
  imports = [
    ./hardware-configuration.nix
    ((builtins.getFlake "github:ReFineID/ReFineID-Unix").nixosModules.default)
  ];
  programs.refineid.enable = true;
  nix.settings = {
    experimental-features = [ "nix-command" "flakes" ];
    # Keep the dependency build in the store across garbage collection,
    # so updates never recompile more than the ReFineID crates.
    keep-outputs = true;
  };
```

Browser card login needs `programs.firefox.enable = true;` -- already
present in the generated `configuration.nix` of a graphical install,
so add it only if it is missing.

then run:

```sh
sudo NIX_CONFIG="experimental-features = nix-command flakes" nixos-rebuild switch
```

The `NIX_CONFIG` prefix is needed only on the first rebuild: `getFlake`
requires flakes, and the config line enabling them has not taken
effect yet. One rebuild later the system has the `refineid` CLI, the
GUI (in the application menu as "ReFineID"), pcscd with the CCID
driver, the PKCS#11 module registered for p11-kit consumers, and
Firefox card login. Plug in a reader and run `refineid card`.

## Updating

The install follows the repository's main branch; updating is another
rebuild:

```sh
sudo NIX_CONFIG="tarball-ttl = 0" nixos-rebuild switch
```

`tarball-ttl = 0` makes Nix fetch the current revision; without it a
rebuild reuses a revision fetched within the last hour. Only the
ReFineID crates recompile on an update -- the dependency build is
reused from the local Nix store until Cargo.lock or the pinned
nixpkgs changes, and `nix.settings.keep-outputs = true` keeps it
there across garbage collection.

The sections below unpack the same install for existing
configurations, flake-based systems, and development.

Three paths: the **system-wide install** (recommended -- one option
enables the CLI, the GUI, the smart-card daemon, and Firefox
integration), the **single-user install** (one account gets the
tools), and the **one-off build** (try it without touching the
system configuration).

## 1. System-wide install (recommended)

Works on any NixOS 26.05 or newer with flakes enabled.
If flakes are not enabled, add to
`/etc/nixos/configuration.nix`:

```nix
nix.settings.experimental-features = [ "nix-command" "flakes" ];
```

### 1a. Flake-based system configuration

Add the input and the module to your system flake:

```nix
{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05";
    refineid = {
      url = "github:ReFineID/ReFineID-Unix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { nixpkgs, refineid, ... }: {
    nixosConfigurations.myhost = nixpkgs.lib.nixosSystem {
      modules = [
        ./configuration.nix
        refineid.nixosModules.default
        { programs.refineid.enable = true; }
      ];
    };
  };
}
```

Then rebuild:

```sh
sudo nixos-rebuild switch --flake /etc/nixos#myhost
```

### 1b. Classic (non-flake) system configuration

In `/etc/nixos/configuration.nix`:

```nix
{ config, pkgs, ... }:
let
  refineid-src = builtins.fetchTarball
    "https://github.com/ReFineID/ReFineID-Unix/archive/main.tar.gz";
in
{
  imports = [
    ((builtins.getFlake "path:${refineid-src}").nixosModules.default)
  ];
  programs.refineid.enable = true;
}
```

(Or clone the repository and use its path in place of the
`fetchTarball`.) Then:

```sh
sudo NIX_CONFIG="experimental-features = nix-command flakes" nixos-rebuild switch
```

### What the option does

`programs.refineid.enable = true` gives you:

- `refineid` and `refineid-gui` in the system PATH, plus a
  "ReFineID" entry in the application launcher;
- `services.pcscd` running with the CCID reader driver -- no separate
  smart-card setup;
- the PKCS#11 module registered system-wide for p11-kit consumers
  (OpenSSL via pkcs11-provider, GnuTLS, OpenSSH) through
  `/etc/pkcs11/modules/refineid.module`;
- Firefox card login configured automatically through the
  `SecurityDevices` enterprise policy **when Firefox is enabled with
  `programs.firefox.enable = true`**. Insert the card, open a
  card-login service, pick the certificate, enter PIN 1. Set
  `programs.refineid.firefoxIntegration = false` to opt out.

### Firefox installed some other way

A Firefox that does not come from `programs.firefox.enable` (home
manager without policies, a tarball install) needs one manual,
per-profile registration:

1. Settings > Privacy & Security > Security Devices > Load.
2. Module name: `ReFineID`.
3. Module filename: the store path printed by
   `readlink -f $(which refineid) | sed 's,/bin/refineid,/lib/librefineid_pkcs11.so,'`

or from a shell:

```sh
modutil -dbdir sql:$HOME/.mozilla/firefox/<profile> \
        -add ReFineID \
        -libfile "$(nix build github:ReFineID/ReFineID-Unix --print-out-paths --no-link)/lib/librefineid_pkcs11.so"
```

## 2. Single-user install (manual Firefox setup)

The system-wide install is the recommended path: it wires Firefox
and every p11-kit consumer automatically. When the tools must stay
in one account, only the smart-card daemon is system-wide and the
rest lives in that user's profile. In `/etc/nixos/configuration.nix`:

```nix
  services.pcscd.enable = true;
  nix.settings = {
    experimental-features = [ "nix-command" "flakes" ];
    keep-outputs = true;
  };
```

then, as the user:

```sh
nix profile add github:ReFineID/ReFineID-Unix
```

That user gets the `refineid` CLI and the GUI, application-menu
entry included; other accounts see nothing. Update with:

```sh
NIX_CONFIG="tarball-ttl = 0" nix profile upgrade --all
```

Firefox card login needs the manual per-profile registration from
the section above, with the module at
`~/.nix-profile/lib/librefineid_pkcs11.so`.

## 3. One-off build (no system changes)

With flakes:

```sh
nix build github:ReFineID/ReFineID-Unix
./result/bin/refineid card          # full card readout
./result/bin/refineid-gui  # the GUI
```

From a clone, without flakes:

```sh
git clone https://github.com/ReFineID/ReFineID-Unix.git
cd ReFineID-Unix
nix-build
./result/bin/refineid card
```

Note: without the system module, pcscd must be running for any card
access -- enable `services.pcscd.enable = true;` in
`configuration.nix` (there is no reliable ad-hoc way to run pcscd on
NixOS).

## 4. Development shell

For hacking on the source:

```sh
nix develop        # flakes; or: nix-shell
cargo build --workspace
cargo test --workspace
cargo run -p refineid-client --bin refineid -- card
cargo run -p refineid-gui
```

The shell provides the toolchain, `pcsc_scan` (reader debugging),
`pkcs11-tool` (module debugging), and the NSS tools (`tstclnt`,
`certutil`, `modutil`) for the hardware cert-auth rig, and sets
`LD_LIBRARY_PATH` so a `cargo run` of the GUI finds the graphics
stack.

### Hardware login test (opt-in)

With a card in the reader and a TLS endpoint that requires a client
certificate, the rig in `crates/refineid-pkcs11/test/` verifies the
full Firefox login path (NSS -> PKCS#11 module -> card PIN -> TLS
`CertificateVerify`) without a browser:

```sh
nix develop        # or: nix-shell
REFINEID_HARDWARE_TEST=1 \
REFINEID_TEST_PIN1=<PIN1> \
HOST=<cert-gated host> REQUEST_PATH=<cert-gated path> \
NSSCKBI="$(nix-build '<nixpkgs>' -A nss --no-out-link)/lib/libnssckbi.so" \
REFINEID_CANONICAL_DYLIB=$PWD/target/release/librefineid_pkcs11.so \
crates/refineid-pkcs11/test/headless-cert-auth.sh
```

Build the module first (`cargo build --release -p refineid-pkcs11`),
or point `REFINEID_CANONICAL_DYLIB` at the installed
`/run/current-system/sw/lib/librefineid_pkcs11.so`. A wrong PIN
consumes a card retry, so double-check `REFINEID_TEST_PIN1` before
running; the module refuses further attempts when the counter runs
low.

## 5. Verifying the install

Reader and card visible:

```sh
pcsc_scan                # should show your reader, and the card when inserted
refineid card            # full readout: identity, certs, PIN counters
```

PKCS#11 module answers:

```sh
# single-user install: ~/.nix-profile/lib/librefineid_pkcs11.so
pkcs11-tool --module /run/current-system/sw/lib/librefineid_pkcs11.so -L
p11-kit list-modules     # shows refineid when the p11-kit config is active
```

Firefox: with the card inserted, Settings > Privacy & Security >
Security Devices should list `ReFineID` with your reader under it,
and a card-login site will prompt for the certificate and PIN 1.

## Troubleshooting

- **Build fails with `rustc was terminated by a deadly signal`.**
  The machine ran out of memory during the final optimisation step,
  which needs several gigabytes on its own. Free up memory (a desktop
  session and parallel compile jobs count against it), give a VM more
  RAM, or add temporary swap and rebuild:

  ```sh
  sudo fallocate -l 8G /var/swapfile
  sudo chmod 600 /var/swapfile
  sudo mkswap /var/swapfile && sudo swapon /var/swapfile
  ```

- **`refineid card` reports no readers.** pcscd is not running
  (`systemctl status pcscd.socket`) or the reader is not attached.
  In a virtual machine, pass the USB reader through to the guest.
- **Firefox shows no certificate prompt.** Check the module is listed
  under Security Devices; a fresh profile enumerates token
  certificates only after the module is registered and the card was
  present when the dialog opened.
- **GUI fails to start with a GL/wayland error.** Run it from the
  installed package (which carries the needed rpath), not by copying
  the bare binary; inside `nix develop`, `LD_LIBRARY_PATH` is already
  set.
- **HTTPS timestamp fetches fail with `no CA bundle found`.** Set
  `REFINEID_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt` (present
  when `security.pki` is at its NixOS defaults).
