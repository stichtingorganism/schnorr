//! Diffie-Hellman key exchange

use mohan::tools::RistrettoBoth;
use crate::keys::{
    SecretKey, 
    PublicKey
};

/// Alias type for a shared secret after ECDH
pub type SharedSecret = RistrettoBoth;

/// Perform a Diffie-Hellman key agreement to produce a `SharedSecret`.
pub fn diffie_hellman(secret: &SecretKey, their_public: &PublicKey) -> SharedSecret {
    RistrettoBoth::from_point(secret.as_scalar() * their_public.as_point())
}


#[cfg(test)]
mod test {
    use super::diffie_hellman;
    use crate::Keypair;

    #[test]
    fn alice_and_bob() {
        let mut csprng = rand::thread_rng();
        let alice: Keypair = Keypair::generate(&mut csprng);
        let bob: Keypair = Keypair::generate(&mut csprng);

        let alice_shared_secret = diffie_hellman(&alice.secret, &bob.public);
        let bob_shared_secret = diffie_hellman(&bob.secret, &alice.public);

        assert_eq!(alice_shared_secret.as_bytes(), bob_shared_secret.as_bytes());
    }
}