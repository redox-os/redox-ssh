extern crate ssh;
use std::io::prelude::*;
use std::fs::File;

pub fn main() {
    let keys = (ssh::key::RSA.generate_key_pair)(1024);
    let mut buffer = File::create("key.pub").unwrap();
    keys.0.write(&mut buffer);
}
