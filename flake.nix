{
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
  inputs.dream2nix = { url = "github:nix-community/dream2nix"; inputs.nixpkgs.follows = "nixpkgs"; };
  inputs.fenix = { url = "github:nix-community/fenix"; inputs.nixpkgs.follows = "nixpkgs"; };

  outputs = { self, nixpkgs, dream2nix, fenix }:
    let
      pkgs = nixpkgs.legacyPackages.x86_64-linux;
      toolchain = fenix.packages.x86_64-linux.toolchainOf {
        channel = "1.61";
        sha256 = "sha256-oro0HsosbLRAuZx68xd0zfgPl6efNj2AQruKRq3KA2g=";
      };
    in
    (dream2nix.lib.makeFlakeOutputs {
      systems = [ "x86_64-linux" ];
      config.projectRoot = ./.;
      source = ./.;
      packageOverrides.tiny-ram-halo2 = {
        set-toolchain.overrideRustToolchain = old: { inherit (toolchain) cargo rustc; };
        freetype-sys.nativeBuildInputs = [ pkgs.cmake ];
        servo-fontconfig-sys = {
          nativeBuildInputs = old: old ++ [ pkgs.pkg-config ];
          buildInputs = [ pkgs.fontconfig ];
        };
      };
    })
    // {
      checks.x86_64-linux.tiny-ram-halo2 = self.packages.x86_64-linux.tiny-ram-halo2;

      devShells.x86_64-linux.default = pkgs.mkShell {
        packages = [
          (toolchain.withComponents [ "rustc" "rustfmt" "rust-src" "cargo" "clippy" "rust-docs" ])
          fenix.packages.x86_64-linux.rust-analyzer
        ];
      };
    };
}
