use key_exchange::{KeyExchange, KeyExchangeResult};
use packet::Packet;

pub struct Curve25519 {

}

impl Curve25519 {
    pub fn new() -> Curve25519 {
        Curve25519 { }
    }
}

impl KeyExchange for Curve25519 {
    fn process(&mut self, packet: &Packet) -> KeyExchangeResult {
        KeyExchangeResult::Ok(None)
    }
}
