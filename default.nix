# Non-flake entry point: nix-build builds the ReFineID package with
# the nixpkgs on NIX_PATH. crane comes pinned from flake.lock so both
# entry points build the same derivation.
{
  pkgs ? import <nixpkgs> { },
}:
let
  lock = builtins.fromJSON (builtins.readFile ./flake.lock);
  crane = fetchTarball {
    url = "https://github.com/ipetkov/crane/archive/${lock.nodes.crane.locked.rev}.tar.gz";
    sha256 = lock.nodes.crane.locked.narHash;
  };
in
pkgs.callPackage ./nix/package.nix { craneLib = import crane { inherit pkgs; }; }
