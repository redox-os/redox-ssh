use std::io::{self, Read, Write};

// mod rsa;
mod ed25519;

// pub use self::rsa::RSA;

pub use self::ed25519::ED25519;

pub trait KeyPair {
    fn system(&self) -> &'static CryptoSystem;

    fn has_private(&self) -> bool;

    fn verify(&self, data: &[u8], signature: &[u8]) -> Result<bool, ()>;
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, ()>;

    fn write_public(&self, w: &mut Write) -> io::Result<()>;
    fn export(&self, w: &mut Write) -> io::Result<()>;
}

pub struct CryptoSystem {
    pub id: &'static str,
    pub generate_key_pair: fn(bits: Option<u32>) -> Box<KeyPair>,
    pub import: fn(r: &mut Read) -> io::Result<Box<KeyPair>>,
    pub read_public: fn(r: &mut Read) -> io::Result<Box<KeyPair>>,
}
