use std::fmt;
use std::io;

pub type ConnectionResult<T> = Result<T, ConnectionError>;

#[derive(Debug)]
pub enum ConnectionError {
    Io(io::Error),
    Protocol,
    Negotiation,
    KeyExchange,
    KeyGeneration,
    Integrity,
}

impl fmt::Display for ConnectionError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::ConnectionError::*;
        write!(
            f,
            "connection error: {}",
            (match &self {
                Io(err) => format!("io error: {}", err),
                Protocol => "protocol error".to_owned(),
                Negotiation => "negotiation error".to_owned(),
                KeyExchange => "key exchange error".to_owned(),
                KeyGeneration => "key generation error".to_owned(),
                Integrity => "integrity error".to_owned(),
            })
        )
    }
}

impl From<io::Error> for ConnectionError {
    fn from(err: io::Error) -> ConnectionError {
        ConnectionError::Io(err)
    }
}
