# Schnorr  [![](https://img.shields.io/crates/v/schnorr.svg)](https://crates.io/crates/schnorr) [![](https://docs.rs/schnorr/badge.svg)](https://docs.rs/schnorr)

A Rust implementation of Schnorr key generation, signing, verification, & multi-signatures.
Furthermore key derivation functionality is supported.

This library aims to be a backbone for many different use cases but we focus on the Public Network needs.

A Multi Signature Protocol is also provided.


**Disclaimers**: 

(1) This code should not be used for production at the moment.

(2) This code is not secure against side-channel attacks

# Installation

To install, add the following to your project's `Cargo.toml`:

```toml
[dependencies.schnorr]
version = "0.0.3"
```

Then, in your library or executable source, add:

```rust
extern crate schnorr;
```

By default, `schnorr` builds against `curve25519-dalek`'s `u64_backend`
feature, which uses Rust's `i128` feature to achieve roughly double the speed as
the `u32_backend` feature.  When targetting 32-bit systems, however, you'll
likely want to compile with
 `cargo build --no-default-features --features="u32_backend"`.
If you're building for a machine with avx2 instructions, there's also the
experimental `avx2_backend`.  To use it, compile with
`RUSTFLAGS="-C target_cpu=native" cargo build --no-default-features --features="avx2_backend"`

# Documentation

Documentation is available [here](https://docs.rs/schnorr).

