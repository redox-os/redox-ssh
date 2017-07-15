use key::{Key, PublicKey, PrivateKey, KeyPair, CryptoSystem};
use std::io::{Read, Write, Result};

pub static RSA: CryptoSystem = CryptoSystem {
    id: "ssh-rsa",
    generate_key_pair: generate_key_pair,
};

pub fn generate_key_pair(size: u32) -> KeyPair {
    let public = Box::new(RsaPublicKey::new());
    let private = Box::new(RsaPrivateKey::new());
    (public, private)
}

pub struct RsaPublicKey {}

impl RsaPublicKey {
    pub fn new() -> RsaPublicKey {
        RsaPublicKey {}
    }
}

impl Key for RsaPublicKey {
    fn system(&self) -> &'static CryptoSystem {
        &RSA
    }

    fn read(&self, r: &mut Read) -> Result<Box<Self>> {
        Err(::std::io::Error::new(::std::io::ErrorKind::Other, ""))
    }

    fn write(&self, w: &mut Write) -> Result<()> {
        Ok(())
    }
}

impl PublicKey for RsaPublicKey {
    fn encrypt(&self, data: &[u8]) -> Vec<u8> {
        Vec::new()
    }
}

pub struct RsaPrivateKey {
}

impl RsaPrivateKey {
    pub fn new() -> RsaPrivateKey {
        RsaPrivateKey { }
    }
}

impl PrivateKey for RsaPrivateKey {
    fn sign(&self, data: &[u8]) -> Vec<u8> {
        Vec::new()
    }
}

impl Key for RsaPrivateKey {
    fn system(&self) -> &'static CryptoSystem {
        &RSA
    }

    fn read(&self, r: &mut Read) -> Result<Box<Self>> {
        Err(::std::io::Error::new(::std::io::ErrorKind::Other, ""))
    }

    fn write(&self, w: &mut Write) -> Result<()> {
        Ok(())
    }
}
