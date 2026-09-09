# Non-flake development shell: nix-shell gives a toolchain and every
# build/runtime dependency for `cargo build` in this tree.
{
  pkgs ? import <nixpkgs> { },
}:
pkgs.mkShell {
  inputsFrom = [ (import ./default.nix { inherit pkgs; }) ];
  packages = with pkgs; [
    clippy
    rustfmt
    pcsc-tools # pcsc_scan for reader debugging
    opensc # pkcs11-tool for module debugging
    nss.tools # tstclnt/certutil/modutil for the hardware cert-auth rig
  ];
  # The GUI dlopens the windowing/GL stack; a dev build has no
  # baked rpath, so provide the libraries via the environment.
  LD_LIBRARY_PATH = pkgs.lib.makeLibraryPath (
    with pkgs;
    [
      libGL
      libxkbcommon
      wayland
      gtk3
      libx11
      libxcursor
      libxi
      libxrandr
    ]
  );
}
