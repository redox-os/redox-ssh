use std::fmt;
use std::io;

pub type ConnectionResult<T> = Result<T, ConnectionError>;

#[derive(Debug)]
pub enum ConnectionError {
    IoError(io::Error),
    ProtocolError,
    NegotiationError,
    KeyExchangeError,
    KeyGenerationError,
    IntegrityError,
}

impl fmt::Display for ConnectionError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::ConnectionError::*;
        write!(f, "connection error: {}", (match &self
        {
            IoError(err) => format!("io error: {}", err),
            ProtocolError => "protocol error".to_owned(),
            NegotiationError => "negotiation error".to_owned(),
            KeyExchangeError => "key exchange error".to_owned(),
            KeyGenerationError => "key generation error".to_owned(),
            IntegrityError => "integrity error".to_owned(),
        }))
    }
}

impl From<io::Error> for ConnectionError {
    fn from(err: io::Error) -> ConnectionError {
        ConnectionError::IoError(err)
    }
}
