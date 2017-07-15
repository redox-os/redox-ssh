extern crate ssh;
extern crate rand;

use rand::Rng;
use std::io::Cursor;
use ssh::key::{self, CryptoSystem, KeyPair};

fn test_export_import(keypair: &Box<KeyPair>) -> Box<KeyPair> {
    let mut buffer = Vec::new();
    keypair.export(&mut buffer).unwrap();

    (keypair.system().import)(&mut Cursor::new(buffer)).unwrap()
}

fn test_crypto_system(system: &CryptoSystem, key_size: Option<u32>) {
    let keypair = (system.generate_key_pair)(key_size);
    let keypair2 = test_export_import(&keypair);

    let mut buffer = [0;4096];
    let mut rng = rand::thread_rng();
    rng.fill_bytes(&mut buffer);

    let signature = keypair.sign(&buffer).unwrap();
    let verified = keypair2.verify(&buffer, signature.as_slice()).unwrap();
    assert!(verified)
}

#[test]
fn test_ed25519() { test_crypto_system(&key::ED25519, None); }
