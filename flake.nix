{
  description = "andro - Android DevOps suite (CLI + daemon + MCP server)";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.11";
    substrate = {
      url = "github:pleme-io/substrate";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    devenv = {
      url = "github:cachix/devenv";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, nixpkgs, substrate, devenv }:
  let
    allSystems = [ "x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin" ];
    forAllSystems = nixpkgs.lib.genAttrs allSystems;
  in {
    packages = forAllSystems (system: let
      pkgs = nixpkgs.legacyPackages.${system};
    in {
      default = pkgs.rustPlatform.buildRustPackage {
        pname = "andro";
        version = "0.1.0";
        src = ./.;
        cargoLock.lockFile = ./Cargo.lock;

        nativeBuildInputs = with pkgs; [ pkg-config ];
        buildInputs = with pkgs; [ openssl ]
          ++ nixpkgs.lib.optionals pkgs.stdenv.isDarwin (
            with pkgs.darwin.apple_sdk.frameworks; [
              Security SystemConfiguration IOKit
            ]
          );

        doCheck = false; # tests need ADB server
      };
    });

    overlays.default = final: prev: {
      andro = self.packages.${final.system}.default;
    };

    homeManagerModules.default = import ./module {
      hmHelpers = import "${substrate}/lib/hm-service-helpers.nix" { lib = nixpkgs.lib; };
    };

    devShells = forAllSystems (system: let
      pkgs = nixpkgs.legacyPackages.${system};
    in {
      default = devenv.lib.mkShell {
        inputs = { inherit nixpkgs devenv; };
        inherit pkgs;
        modules = [
          (import "${substrate}/lib/devenv/rust.nix")
          {
            packages = with pkgs; [ android-tools ];
            env.ANDRO_CONFIG = "";
          }
        ];
      };
    });
  };
}
