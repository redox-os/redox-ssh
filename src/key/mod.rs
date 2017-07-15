use std::io::{Result, Read, Write};

mod rsa;

pub use self::rsa::RSA;

pub trait Key {
    fn system(&self) -> &'static CryptoSystem;

    fn read(&self, r: &mut Read) -> Result<Box<Self>>
    where
        Self: Sized;

    fn import(&self, r: &mut Read) -> Result<Box<Self>>
    where
        Self: Sized,
    {
        self.read(r)
    }

    fn write(&self, w: &mut Write) -> Result<()>;

    fn export(&self, w: &mut Write) -> Result<()> {
        self.write(w)
    }
}

pub trait PublicKey: Key {
    fn encrypt(&self, data: &[u8]) -> Vec<u8>;
}

pub trait PrivateKey: Key {
    fn sign(&self, data: &[u8]) -> Vec<u8>;
}

type KeyPair = (Box<PublicKey>, Box<PrivateKey>);

pub struct CryptoSystem {
    pub id: &'static str,
    pub generate_key_pair: fn(bits: u32) -> KeyPair
}
