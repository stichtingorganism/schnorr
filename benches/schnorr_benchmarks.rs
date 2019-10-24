// Copyright 2019 Stichting Organism
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// -*- mode: rust; -*-
//
// This file is part of ed25519-dalek.
// Copyright (c) 2018 Isis Lovecruft
// See LICENSE for licensing information.
//
// Authors:
// - Isis Agora Lovecruft <isis@patternsinthevoid.net>

#[macro_use]
extern crate criterion;
extern crate blake2;
extern crate merlin;
extern crate rand;
extern crate schnorr;

mod schnorr_benches {
    use criterion::Criterion;

    use schnorr::prelude::*;

    use merlin::Transcript;
    // use blake2::Blake2b;
    use rand::prelude::{thread_rng, ThreadRng};

    fn sign(c: &mut Criterion) {
        let mut csprng: ThreadRng = thread_rng();
        let keypair: Keypair = Keypair::generate(&mut csprng);
        let msg: &[u8] = b"";

        let ctx = SigningContext::new(b"this signature does this thing");

        c.bench_function("Schnorr signing", move |b| {
            b.iter(|| keypair.sign(ctx.bytes(msg)))
        });
    }

    fn verify(c: &mut Criterion) {
        let mut csprng: ThreadRng = thread_rng();
        let keypair: Keypair = Keypair::generate(&mut csprng);
        let msg: &[u8] = b"";
        let ctx = SigningContext::new(b"this signature does this thing");
        let sig: Signature = keypair.sign(ctx.bytes(msg));

        c.bench_function("Schnorr signature verification", move |b| {
            b.iter(|| keypair.verify(ctx.bytes(msg), &sig))
        });
    }

    fn verify_batch_signatures(c: &mut Criterion) {
        static BATCH_SIZES: [usize; 8] = [4, 8, 16, 32, 64, 96, 128, 256];

        c.bench_function_over_inputs(
            "Schnorr batch signature verification",
            |b, &&size| {
                let mut csprng: ThreadRng = thread_rng();
                let keypairs: Vec<Keypair> =
                    (0..size).map(|_| Keypair::generate(&mut csprng)).collect();
                let msg: &[u8] = b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
                let ctx = SigningContext::new(b"this signature does this thing");
                let signatures: Vec<Signature> = keypairs
                    .iter()
                    .map(|key| key.sign(ctx.bytes(msg)))
                    .collect();
                let public_keys: Vec<PublicKey> = keypairs.iter().map(|key| key.public).collect();

                b.iter(|| {
                    let transcripts: Vec<Transcript> = ::std::iter::once(ctx.bytes(msg))
                        .cycle()
                        .take(size)
                        .collect();
                    verify_batch(&transcripts[..], &signatures[..], &public_keys[..])
                });
            },
            &BATCH_SIZES,
        );
    }

    fn key_generation(c: &mut Criterion) {
        let mut csprng: ThreadRng = thread_rng();

        c.bench_function("Schnorr keypair generation", move |b| {
            b.iter(|| Keypair::generate(&mut csprng))
        });
    }

    criterion_group! {
        name = schnorr_benches;
        config = Criterion::default();
        targets =
            sign,
            verify,
            verify_batch_signatures,
            key_generation,
    }
}

criterion_main!(schnorr_benches::schnorr_benches,);
