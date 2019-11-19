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


mod schnorr_benches {
    use criterion::Criterion;
    use schnorr::*;
    use bacteria::Transcript;

    fn sign(c: &mut Criterion) {
        let keypair: Keypair = Keypair::generate(&mut mohan::mohan_rand());

        let ctx = SigningContext::new(b"this signature does this thing");
        let mut t = ctx.bytes(b"yummy");

        c.bench_function("Schnorr signing", move |b| {
            b.iter(|| Signature::sign(&mut t, &keypair.secret))
        });
    }

    fn verify(c: &mut Criterion) {
        let keypair: Keypair = Keypair::generate(&mut mohan::mohan_rand());
        let ctx = SigningContext::new(b"this signature does this thing");
        let mut t = ctx.bytes(b"yummy");
        let sig: Signature = Signature::sign(&mut t, &keypair.secret);

        c.bench_function("Schnorr signature verification", move |b| {
            b.iter(|| sig.verify(&mut t, &keypair.public))
        });
    }

    fn verify_batch_signatures(c: &mut Criterion) {
        static BATCH_SIZES: [usize; 8] = [4, 8, 16, 32, 64, 96, 128, 256];

        c.bench_function_over_inputs(
            "Schnorr batch signature verification",
            |b, &&size| {
                let keypairs: Vec<Keypair> =
                    (0..size).map(|_| Keypair::generate(&mut mohan::mohan_rand())).collect();
                let msg: &[u8] = b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
                let ctx = SigningContext::new(b"this signature does this thing");
                let signatures: Vec<Signature> = keypairs
                    .iter()
                    .map(|key| Signature::sign(&mut ctx.bytes(msg), &key.secret))
                    .collect();
                let public_keys: Vec<PublicKey> = keypairs.iter().map(|key| key.public).collect();

               
                let mut transcripts: Vec<Transcript> = ::std::iter::once(ctx.bytes(msg))
                        .cycle()
                        .take(size)
                        .collect();

                b.iter(|| {
                    let mut batch = BatchVerifier::new(&mut mohan::mohan_rand());
                    for i in 0..signatures.len() {
                        signatures[i].verify_batched(&mut transcripts[i], &public_keys[i], &mut batch);
                    }
                   batch.verify()
                });
            },
            &BATCH_SIZES,
        );
    }


    criterion_group! {
        name = schnorr_benches;
        config = Criterion::default();
        targets =
            sign,
            verify,
            verify_batch_signatures,
    }
}

criterion_main!(schnorr_benches::schnorr_benches);
