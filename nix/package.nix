# ReFineID package: the refineid CLI, the ReFineID GUI, and the
# PKCS#11 module, built from this source tree with the Rust that
# nixpkgs ships.
#
# Built with crane so the dependency graph compiles as its own
# derivation: editing ReFineID source rebuilds only the workspace
# crates, while the dependency build is reused from the local store
# until Cargo.lock (or the toolchain) changes.
{
  lib,
  craneLib,
  pkg-config,
  # GTK apps abort without the GSettings machinery in their
  # environment (the file chooser reads org.gtk.Settings.FileChooser).
  wrapGAppsHook3,
  gsettings-desktop-schemas,
  pcsclite,
  fontconfig,
  # GTK 3 backs the file-chooser dialog (rfd gtk3 backend); linked at
  # build time.
  gtk3,
  # Windowing stack for the Slint (winit) GUI. The software renderer
  # needs no GL. dlopened at runtime, so on the rpath.
  libxkbcommon,
  wayland,
  libx11,
  libxcursor,
  libxi,
  libxrandr,
}:

let
  commonArgs = {
    pname = "refineid";
    version = lib.trim (builtins.readFile ../VERSION);

    src = lib.cleanSourceWith {
      src = ../.;
      # Documentation is excluded so a doc-only commit does not
      # recompile the workspace.
      filter =
        path: type:
        let
          base = baseNameOf path;
        in
        base != "target"
        && base != "result"
        && base != ".git"
        && base != "nix"
        && base != "doc"
        && !lib.hasSuffix ".md" base;
    };

    strictDeps = true;
    # Identical for the dependency build and the final build: any
    # difference in the environment invalidates cargo's fingerprints
    # and recompiles cached dependencies for nothing.
    nativeBuildInputs = [
      pkg-config
      wrapGAppsHook3
    ];
    # Only the GUI needs the GTK wrap; leave the CLI and the PKCS#11
    # module unwrapped (wrapGApp runs in postFixup).
    dontWrapGApps = true;
    buildInputs = [
      pcsclite
      fontconfig
      gtk3
      gsettings-desktop-schemas
    ];
  };

  # Dependencies only: crane builds this from the manifests and
  # Cargo.lock with dummied-out workspace sources, so its hash -- and
  # therefore the cached artifact -- survives ReFineID source edits.
  # The version is pinned so a version stamp does not rotate the
  # cached derivation by name alone (the stamp still rebuilds it
  # through .cargo/config.toml, which the dependency build must see
  # for its rustflags).
  cargoArtifacts = craneLib.buildDepsOnly (commonArgs // { version = "0"; });
in
craneLib.buildPackage (
  commonArgs
  // {
    inherit cargoArtifacts;

    # The GUI dlopens its windowing stack at runtime.
    runtimeLibs = lib.makeLibraryPath [
      libxkbcommon
      wayland
      libx11
      libxcursor
      libxi
      libxrandr
    ];

    postFixup = ''
      patchelf --add-rpath "$runtimeLibs" $out/bin/refineid-gui
      wrapGApp $out/bin/refineid-gui
    '';

    postInstall = ''
      # The PKCS#11 cdylib (installed from the cargo build log; copy
      # by hand if the crane hook missed it, and assert so a hook
      # change cannot ship a package silently missing the module).
      if [ ! -f $out/lib/librefineid_pkcs11.so ]; then
        mkdir -p $out/lib
        cp target/release/librefineid_pkcs11.so $out/lib/
      fi
      test -f $out/lib/librefineid_pkcs11.so

      # p11-kit module config: every p11-kit-aware consumer (Firefox
      # via p11-kit-proxy, OpenSSL via pkcs11-provider, GnuTLS,
      # OpenSSH) loads the module with no per-user configuration.
      mkdir -p $out/share/p11-kit/modules
      cat > $out/share/p11-kit/modules/refineid.module <<EOF
      module: $out/lib/librefineid_pkcs11.so
      # Citizen client-auth keys, not CA trust anchors.
      trust-policy: no
      # A load failure must not take down every crypto consumer.
      critical: no
      EOF

      # Desktop entry + icon for the GUI. The visible name is "ReFineID";
      # the binary is refineid-gui so it does not collide with the
      # `refineid` CLI on PATH.
      mkdir -p $out/share/applications $out/share/icons/hicolor/scalable/apps
      cp crates/refineid-gui/assets/app-icon.svg \
        $out/share/icons/hicolor/scalable/apps/refineid.svg
      cat > $out/share/applications/refineid.desktop <<EOF
      [Desktop Entry]
      Type=Application
      Name=ReFineID
      GenericName=Identity card tool
      Comment=Finnish identity card: PIN management, portrait and signature, document signing
      Exec=$out/bin/refineid-gui
      Icon=refineid
      Terminal=false
      Categories=Utility;Security;
      Keywords=FINEID;smartcard;PIN;identity;signing;
      EOF
    '';

    meta = {
      description = "Open-source FINEID middleware: CLI, PKCS#11 module, and desktop GUI";
      homepage = "https://github.com/ReFineID/ReFineID-Unix";
      license = lib.licenses.asl20;
      platforms = lib.platforms.linux;
      mainProgram = "refineid";
    };
  }
)
