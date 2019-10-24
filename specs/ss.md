
https://github.com/ElementsProject/secp256k1-zkp/blob/secp256k1-zkp/src/modules/musig/musig.md
## Atomic Swaps

The signing API supports the production of "adaptor signatures", modified partial signatures
which are offset by an auxiliary secret known to one party. That is,
1. One party generates a (secret) adaptor `t` with corresponding (public) adaptor `T = t*G`.
2. When combining nonces, each party adds `T` to the total nonce used in the signature.
3. The party who knows `t` must "adapt" their partial signature with `t` to complete the
   signature.
4. Any party who sees both the final signature and the original partial signatures
   can compute `t`.

Using these adaptor signatures, two 2-of-2 MuSig signing protocols can be executed in
parallel such that one party's partial signatures are made atomic. That is, when the other
party learns one partial signature, she automatically learns the other. This has applications
in cross-chain atomic swaps.

Such a protocol can be executed as follows. Consider two participants, Alice and Bob, who
are simultaneously producing 2-of-2 multisignatures for two blockchains A and B. They act
as follows.

1. Before the protocol begins, Bob chooses a 32-byte auxiliary secret `t` at random and
   computes a corresponding public point `T` by calling `secp256k1_ec_pubkey_create`.
   He communicates `T` to Alice.
2. Together, the parties execute steps 1-4 of the signing protocol above.
3. At step 5, when combining the two parties' public nonces, both parties call
   `secp256k1_musig_session_combine_nonces` with `adaptor` set to `T` and `nonce_is_negated`
   set to a non-NULL pointer to int.
4. Steps 6 and 7 proceed as before. Step 8, verifying the partial signatures, is now
   essential to the security of the protocol and must not be omitted!

The above steps are executed identically for both signing sessions. However, step 9 will
not work as before, since the partial signatures will not add up to a valid total signature.
Additional steps must be taken, and it is at this point that the two signing sessions
diverge. From here on we consider "Session A" which benefits Alice (e.g. which sends her
coins) and "Session B" which benefits Bob (e.g. which sends him coins).

5. In Session B, Bob calls `secp256k1_musig_partial_sig_adapt` with his partial signature
   and `t`, to produce an adaptor signature. He can then call `secp256k1_musig_partial_sig_combine`
   with this adaptor signature and Alice's partial signature, to produce a complete
   signature for blockchain B.
6. Alice reads this signature from blockchain B. She calls `secp256k1_musig_extract_secret_adaptor`,
   passing the complete signature along with her and Bob's partial signatures from Session B.
   This function outputs `t`, which until this point was only known to Bob.
7. In Session A, Alice is now able to replicate Bob's action, calling
   `secp256k1_musig_partial_sig_adapt` with her own partial signature and `t`, ultimately
   producing a complete signature on blockchain A.
