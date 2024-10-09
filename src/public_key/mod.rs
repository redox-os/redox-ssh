use std::io::{self, Read, Write};

mod ed25519;
// mod rsa;

pub use self::ed25519::ED25519;
// pub use self::rsa::RSA;

pub trait KeyPair: Sync + Send {
    fn system(&self) -> &'static CryptoSystem;

    fn has_private(&self) -> bool;

    fn verify(
        &self,
        data: &[u8],
        signature: &[u8],
    ) -> Result<bool, KeyPairIdValidationError>;
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, SigningError>;

    fn write_public(&self, w: &mut dyn Write) -> io::Result<()>;
    fn export(&self, w: &mut dyn Write) -> io::Result<()>;
}

pub struct CryptoSystem {
    pub id: &'static str,
    pub generate_key_pair: fn(bits: Option<u32>) -> Box<dyn KeyPair>,
    pub import: fn(r: &mut dyn Read) -> io::Result<Box<dyn KeyPair>>,
    pub read_public: fn(r: &mut dyn Read) -> io::Result<Box<dyn KeyPair>>,
}

#[derive(Debug)]
pub enum SigningError {
    NoPrivateKey,
    Io(io::Error),
}

impl From<io::Error> for SigningError {
    fn from(value: io::Error) -> Self {
        SigningError::Io(value)
    }
}

#[derive(Debug)]
pub struct KeyPairIdValidationError<'a> {
    pub expected_id: &'a [u8],
    pub received_id: Vec<u8>,
}
