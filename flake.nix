{
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
  inputs.dream2nix = { url = "github:nix-community/dream2nix"; inputs.nixpkgs.follows = "nixpkgs"; };
  inputs.fenix = { url = "github:nix-community/fenix"; inputs.nixpkgs.follows = "nixpkgs"; };

  outputs = { self, nixpkgs, dream2nix, fenix }:
    let
      pkgs = nixpkgs.legacyPackages.x86_64-linux;
      toolchain = fenix.packages.x86_64-linux.fromToolchainFile { file = ./rust-toolchain; };
    in
    (dream2nix.lib.makeFlakeOutputs {
      systems = [ "x86_64-linux" ];
      config.projectRoot = ./.;
      source = ./.;
      packageOverrides.tiny-ram-halo2 = {
        set-toolchain.overrideRustToolchain = old: { inherit (toolchain); };
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
          pkgs.rustup
          fenix.packages.x86_64-linux.rust-analyzer
          pkgs.cmake
          pkgs.pkg-config
          pkgs.fontconfig
        ];
      };
    };
}
