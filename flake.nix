{
  inputs =
    {
      # cargo2nix.url = "github:cargo2nix/cargo2nix";
      # We have to use the fork to fix nix build https://github.com/cargo2nix/cargo2nix/issues/233
      cargo2nix.url = "github:flibrary/cargo2nix";
      nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
      rust-overlay.url = "github:oxalica/rust-overlay";
      flake-utils.url = "github:numtide/flake-utils";
    };

  outputs = { self, cargo2nix, flake-utils, nixpkgs, rust-overlay, ... }:
    with builtins;
    flake-utils.lib.eachDefaultSystem
      (system:
        let
          pkgs =
            import nixpkgs
              {
                overlays =
                  [
                    (import "${cargo2nix}/overlay")
                    rust-overlay.overlay
                  ];

                inherit system;
              };

          rustChannel = "1.59.0";
          rustPkgs =
            pkgs.rustBuilder.makePackageSet'
              {
                inherit rustChannel;
                packageFun = import ./Cargo.nix;
                packageOverrides =
                  let
                    expat-sys = pkgs.rustBuilder.rustLib.makeOverride {
                      name = "expat-sys";
                      overrideAttrs = drv: {
                        propagatedBuildInputs = drv.propagatedBuildInputs or [ ] ++ [ pkgs.expat ];
                      };
                    };
                    freetype-sys = pkgs.rustBuilder.rustLib.makeOverride {
                      name = "freetype-sys";
                      overrideAttrs = drv: {
                        propagatedBuildInputs = drv.propagatedBuildInputs or [ ] ++ [ pkgs.freetype ];
                      };
                    };
                    font-kit = pkgs.rustBuilder.rustLib.makeOverride {
                      name = "font-kit";
                      overrideAttrs = drv: {
                        propagatedNativeBuildInputs = drv.propagatedNativeBuildInputs or [ ] ++ [ pkgs.noto-fonts pkgs.fontconfig ];
                      };
                    };
                  in
                  pkgs: pkgs.rustBuilder.overrides.all ++ [ expat-sys freetype-sys font-kit ];
              };
        in
        rec
        {
          packages =
            {
              tiny-ram-halo2 = (rustPkgs.workspace.tiny-ram-halo2 { }).bin;

              # `runTests` runs all tests for a crate inside a Nix derivation.  This
              # may be problematic as Nix may restrict filesystem, network access,
              # socket creation, which the test binary may need.
              # If you run to those problems, build test binaries (as shown above in
              # workspace derivation arguments) and run them manually outside a Nix
              # derivation.s
              ci = pkgs.rustBuilder.runTests rustPkgs.workspace.tiny-ram-halo2 {
                # Add `depsBuildBuild` test-only deps here, if any.

                FONTCONFIG_FILE =
                  with pkgs;
                  makeFontsConf
                    { inherit fontconfig;
                      fontDirectories = [ "${noto-fonts}" ];
                    };
              };
              shell = devShell;
            };

          defaultPackage = packages.tiny-ram-halo2;

          devShell =
            let
              rust-toolchain =
                (pkgs.formats.toml { }).generate "rust-toolchain.toml"
                  {
                    toolchain =
                      {
                        channel = rustChannel;

                        components =
                          [
                            "rustc"
                            "rustfmt"
                            "rust-src"
                            "cargo"
                            "clippy"
                            "rust-docs"
                          ];
                      };
                  };
            in
            rustPkgs.workspaceShell {
              # inherit rustChannel;
              nativeBuildInputs = with pkgs; [ rust-analyzer rustup cargo2nix.defaultPackage.${system} graphviz ];
              shellHook =
                ''
                  cp --no-preserve=mode ${rust-toolchain} rust-toolchain.toml

                  export RUST_SRC_PATH=~/.rustup/toolchains/${rustChannel}-x86_64-unknown-linux-gnu/lib/rustlib/src/rust/library/
                '';
            };

            herculesCI.ciSystems = [ "x86_64-linux" ];
        }
      );
}
