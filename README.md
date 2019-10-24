# Schnorr  [![](https://img.shields.io/crates/v/schnorr.svg)](https://crates.io/crates/schnorr) [![](https://docs.rs/schnorr/badge.svg)](https://docs.rs/schnorr) [![Gitter](https://badges.gitter.im/stichtingorganism/community.svg)](https://gitter.im/stichtingorganism/community?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge)

A Rust implementation of Schnorr key generation, signing, verification, & multi-signatures.
Furthermore key derivation functionality is supported.

This library aims to be a backbone for many different use cases but we focus on the Public Network needs.

A Multi Signature Protocol is also provided.


**Disclaimers**: 

(1) This code should not be used for production at the moment.

(2) This code is not secure against side-channel attacks

(3) Little Endian Platforms ONLY

# Bounty
We are running a Bug Bounty for this library. Please submit a PR with issue + fix and the crypto address of the coin you want.
We  will send

- $200 For Major Bugs: Key Recovery, 
- $100 Wrong function procedures that cause major issues
- $10 for Minor bugs 

Other amounts can be given based on issues. We want a solid library for the community. Audits are very expensive
so we choose to create an open bounty problem to get help from the world and give back what we can right now.



# Installation

To install, add the following to your project's `Cargo.toml`:

```toml
[dependencies.schnorr]
version = "0.0.5"
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

