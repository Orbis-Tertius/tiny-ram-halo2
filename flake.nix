{ inputs =
    { cargo2nix.url = "github:cargo2nix/cargo2nix";
      nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
      rust-overlay.url = "github:oxalica/rust-overlay";
      flake-utils.url = "github:numtide/flake-utils";
    };

  outputs = { cargo2nix, flake-utils, nixpkgs, rust-overlay, ... }:
    with builtins;
    flake-utils.lib.eachDefaultSystem
      (system:
         let
           pkgs =
             import nixpkgs
               { overlays =
                   [ (import "${cargo2nix}/overlay")
                     rust-overlay.overlay
                   ];

                 inherit system;
               };

            rustChannel = "1.59.0";
             rustPkgs =
               pkgs.rustBuilder.makePackageSet'
                 { inherit rustChannel;
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
                    in
                    pkgs: pkgs.rustBuilder.overrides.all ++ [ expat-sys freetype-sys ];
                 };
         in
         { defaultPackage = rustPkgs.workspace.tiny-ram-halo2 {};

           devShell =
             let
               rust-toolchain =
                 (pkgs.formats.toml {}).generate "rust-toolchain.toml"
                   { toolchain =
                       { channel = rustChannel;

                         components =
                           [ "rustc"
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
                   # cp --no-preserve=mode ${rust-toolchain} rust-toolchain.toml

                   export RUST_SRC_PATH=~/.rustup/toolchains/${rustChannel}-x86_64-unknown-linux-gnu/lib/rustlib/src/rust/library/
                   '';
               };
         }
      );
}
