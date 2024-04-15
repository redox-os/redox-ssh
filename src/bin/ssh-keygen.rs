extern crate ssh;
use std::fs::File;

use ssh::public_key;

pub fn main() {
    let keypair = (public_key::ED25519.generate_key_pair)(None);
    let mut buffer = File::create("server.key").unwrap();
    let _ = keypair.export(&mut buffer);
}
