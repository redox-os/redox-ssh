extern crate ssh;
extern crate rand;

use std::io::Cursor;

use rand::Rng;
use ssh::public_key::{self, CryptoSystem, KeyPair};

fn test_export_import(keypair: &Box<KeyPair>) -> Box<KeyPair> {
    // Export the keypair to a vector and import it again
    let mut buffer = Vec::new();
    keypair.export(&mut buffer).unwrap();
    (keypair.system().import)(&mut Cursor::new(buffer)).unwrap()
}

fn test_crypto_system(system: &CryptoSystem, key_size: Option<u32>) {
    // Generate a key pair
    let keypair = (system.generate_key_pair)(key_size);

    // Export and import that key pair again
    let keypair2 = test_export_import(&keypair);

    // Generate a random message
    let mut buffer = [0; 4096];
    let mut rng = rand::thread_rng();
    rng.fill_bytes(&mut buffer);

    // Sign the message and verify it
    let signature = keypair.sign(&buffer).unwrap();
    let verified = keypair2.verify(&buffer, signature.as_slice()).unwrap();
    assert!(verified);

    // Corrupt random message and try again
    buffer[2342] = !buffer[2342];
    let verified = keypair2.verify(&buffer, signature.as_slice()).unwrap();
    assert!(!verified);
}

#[test]
fn test_ed25519() {
    test_crypto_system(&public_key::ED25519, None);
}
