# tiny-ram-halo2

This repo is in the early stages of development.
It will contain a implementation of a TinyRAM execution verifier using the [halo2](https://github.com/zcash/halo2).

## Building or Testing

You do not need `rustc`, `cargo`, or `rust-analyzer` installed on your system. They are provided by this repository's nix flake.
```bash
# Enter a nix shell
nix develop

# Edit

# Run tests
cargo test
```

### To run test's exactly as our CI does:

`nix build ./#ci`
