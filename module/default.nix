# Home-manager module for andro MCP server registration.
#
# Usage:
#   services.andro = {
#     enable = true;
#     mcp.enable = true;
#   };
{ hmHelpers }:
{ lib, config, pkgs, ... }:
with lib; let
  inherit (hmHelpers) mkMcpOptions mkMcpServerEntry;
  cfg = config.services.andro;
in {
  options.services.andro = {
    enable = mkEnableOption "andro Android DevOps suite";

    package = mkOption {
      type = types.package;
      default = pkgs.andro;
      description = "The andro package";
    };

    mcp = mkMcpOptions {
      defaultPackage = cfg.package;
      defaultPackageText = "config.services.andro.package";
    };
  };

  config = mkIf cfg.enable {
    home.packages = [ cfg.package ];

    services.andro.mcp.serverEntry = mkIf cfg.mcp.enable (
      mkMcpServerEntry {
        command = "${cfg.mcp.package}/bin/andro";
        args = [ "mcp" ];
      }
    );
  };
}
