{
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
  inputs.dream2nix = { url = "github:nix-community/dream2nix"; inputs.nixpkgs.follows = "nixpkgs"; };
  inputs.fenix = { url = "github:nix-community/fenix"; inputs.nixpkgs.follows = "nixpkgs"; };

  outputs = { self, nixpkgs, dream2nix, fenix }:
    let
      pkgs = nixpkgs.legacyPackages.x86_64-linux;
      channelVersion = "1.64.0";
      toolchain = fenix.packages.x86_64-linux.toolchainOf {
        channel = channelVersion;
        sha256 = "sha256-8len3i8oTwJSOJZMosGGXHBL5BVuGQnWOT2St5YAUFU=";
      };
    in
    (dream2nix.lib.makeFlakeOutputs {
      systems = [ "x86_64-linux" ];
      config.projectRoot = ./.;
      source = ./.;
      packageOverrides.tiny-ram-halo2 = {
        set-toolchain.overrideRustToolchain = old: { inherit (toolchain) cargo rustc; };
        freetype-sys.nativeBuildInputs = old: old ++ [ pkgs.cmake ];
        expat-sys.nativeBuildInputs = old: old ++ [ pkgs.cmake ];
        servo-fontconfig-sys = {
          nativeBuildInputs = old: old ++ [ pkgs.pkg-config ];
          buildInputs = old: old ++ [ pkgs.fontconfig ];
        };
      };
    })
    // {
      checks.x86_64-linux.tiny-ram-halo2 = self.packages.x86_64-linux.tiny-ram-halo2;

      devShells.x86_64-linux.default =
        let
          rust-toolchain = (pkgs.formats.toml { }).generate "rust-toolchain.toml" {
            toolchain = {
              channel = channelVersion;
              components = [ "rustc" "rustfmt" "rust-src" "cargo" "clippy" "rust-docs" ];
            };
          };
        in
        pkgs.mkShell {
          shellHook = "cp --no-preserve=mode ${rust-toolchain} rust-toolchain.toml";
          packages = [
            pkgs.rustup
            fenix.packages.x86_64-linux.rust-analyzer
            pkgs.cmake
            pkgs.pkg-config
            pkgs.fontconfig
          ];
        };
    };
}
