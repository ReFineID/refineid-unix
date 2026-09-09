{
  description = "ReFineID -- open-source FINEID middleware for Finnish identity cards";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05";
    # Splits the cargo build so dependencies compile as their own
    # locally cached derivation; source edits rebuild only our crates.
    crane.url = "github:ipetkov/crane";
  };

  outputs =
    {
      self,
      nixpkgs,
      crane,
    }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
      ];
      forAllSystems = f: nixpkgs.lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});
      packageFor = pkgs: pkgs.callPackage ./nix/package.nix { craneLib = crane.mkLib pkgs; };
    in
    {
      packages = forAllSystems (pkgs: rec {
        refineid = packageFor pkgs;
        default = refineid;
      });

      nixosModules = {
        refineid = import ./nix/module.nix { refineidPackage = packageFor; };
        default = self.nixosModules.refineid;
      };

      overlays.default = final: prev: { refineid = packageFor final; };

      devShells = forAllSystems (pkgs: {
        default = import ./shell.nix { inherit pkgs; };
      });
    };
}
