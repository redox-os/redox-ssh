use std::convert::From;
use std::error::Error;
use std::fmt;
use std::io;

pub type ConnectionResult<T> = Result<T, ConnectionError>;

#[derive(Debug)]
pub enum ConnectionError {
    IoError(io::Error),
    ProtocolError,
    NegotiationError,
    KeyExchangeError,
}

impl fmt::Display for ConnectionError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "connection error: {}", (self as &Error).description())
    }
}

impl Error for ConnectionError {
    fn description(&self) -> &str {
        use self::ConnectionError::*;
        match self
        {
            &IoError(_) => "io error",
            &ProtocolError => "protocol error",
            &NegotiationError => "negotiation error",
            &KeyExchangeError => "key exchange error",
        }
    }
}

impl From<io::Error> for ConnectionError {
    fn from(err: io::Error) -> ConnectionError {
        ConnectionError::IoError(err)
    }
}
