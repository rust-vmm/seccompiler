# v0.3.0

## Changed
- [[#40]](https://github.com/rust-vmm/seccompiler/pull/40): Update Rust
  to Edition 2021

## Fixed

- [[#31]](https://github.com/rust-vmm/seccompiler/issues/31): Implement
  `From<BackendError>` for `Error`
- [[#40]](https://github.com/rust-vmm/seccompiler/pull/40): Fix clippy
  complaints about missing `Eq` when `PartialEq` is implemented

# v0.2.0

First release

## Added

- [[#7]](https://github.com/rust-vmm/seccompiler/pull/7): Add functionality for
  Rust-based filters and implement the BPF compilation logic.
- [[#9]](https://github.com/rust-vmm/seccompiler/pull/9): Add json frontend,
  gated by the `json` feature.
