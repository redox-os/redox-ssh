extern crate ssh;
use std::io::prelude::*;
use std::fs::File;

pub fn main() {
    let keypair = (ssh::key::ED25519.generate_key_pair)(None);
    let mut buffer = File::create("key.pub").unwrap();
    keypair.export(&mut buffer);
}
