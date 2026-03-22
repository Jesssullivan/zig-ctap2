{
  description = "zig-ctap2 — Portable CTAP2/FIDO2 library in Zig";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    flake-parts.url = "github:hercules-ci/flake-parts";
  };

  outputs = inputs @ { flake-parts, ... }:
    flake-parts.lib.mkFlake { inherit inputs; } {
      systems = [ "x86_64-linux" "aarch64-linux" "aarch64-darwin" ];

      perSystem = { pkgs, system, ... }:
        let
          zig = pkgs.zig_0_14;  # closest available in nixpkgs; override if 0.15 lands
        in
        {
          devShells.default = pkgs.mkShell {
            packages = [
              zig
              pkgs.just
              pkgs.python3Packages.detect-secrets
              pkgs.pre-commit
            ] ++ pkgs.lib.optionals pkgs.stdenv.isDarwin [
              pkgs.darwin.apple_sdk.frameworks.IOKit
              pkgs.darwin.apple_sdk.frameworks.CoreFoundation
            ];

            shellHook = ''
              echo "zig-ctap2 dev shell — zig $(zig version 2>/dev/null || echo 'not found')"
            '';
          };

          packages.default = pkgs.stdenv.mkDerivation {
            pname = "zig-ctap2";
            version = "0.2.0";
            src = ./.;

            nativeBuildInputs = [ zig ];
            buildInputs = pkgs.lib.optionals pkgs.stdenv.isDarwin [
              pkgs.darwin.apple_sdk.frameworks.IOKit
              pkgs.darwin.apple_sdk.frameworks.CoreFoundation
            ];

            dontConfigure = true;

            buildPhase = ''
              export XDG_CACHE_HOME="$TMPDIR/zig-cache"
              zig build -Doptimize=ReleaseFast --prefix $out
            '';

            installPhase = ''
              mkdir -p $out/include
              cp include/ctap2.h $out/include/
            '';
          };
        };
    };
}
