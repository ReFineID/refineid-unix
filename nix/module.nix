# NixOS module: everything a FINEID card user needs, in one option.
#
#   programs.refineid.enable = true;
#
# gives you the refineid CLI, the ReFineID GUI, the PKCS#11
# module registered system-wide for p11-kit consumers, the pcscd
# smart-card daemon, and (when Firefox is managed by NixOS) automatic
# Firefox card-login integration via the SecurityDevices policy.
{ refineidPackage }:
{
  config,
  lib,
  pkgs,
  ...
}:
let
  cfg = config.programs.refineid;
in
{
  options.programs.refineid = {
    enable = lib.mkEnableOption "ReFineID Finnish identity card middleware";

    package = lib.mkOption {
      type = lib.types.package;
      default = refineidPackage pkgs;
      defaultText = lib.literalExpression "refineid packaged from this flake";
      description = "The ReFineID package to install.";
    };

    firefoxIntegration = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = ''
        Register the ReFineID PKCS#11 module in Firefox through the
        SecurityDevices enterprise policy, so card login works with no
        per-user setup. Takes effect when Firefox is enabled through
        {option}`programs.firefox.enable`; a Firefox installed some
        other way needs the manual registration described in
        doc/install-nixos.md.
      '';
    };
  };

  config = lib.mkIf cfg.enable {
    environment.systemPackages = [ cfg.package ];

    # The PC/SC smart-card daemon (with the CCID reader driver).
    services.pcscd.enable = true;

    # System-wide p11-kit registration: OpenSSL (pkcs11-provider),
    # GnuTLS, and OpenSSH discover the card through p11-kit.
    environment.etc."pkcs11/modules/refineid.module".source =
      "${cfg.package}/share/p11-kit/modules/refineid.module";

    # Firefox does not consult p11-kit on NixOS; the enterprise
    # policy loads the module directly.
    programs.firefox.policies = lib.mkIf cfg.firefoxIntegration {
      SecurityDevices.Add = {
        "ReFineID" = "${cfg.package}/lib/librefineid_pkcs11.so";
      };
    };
  };
}
