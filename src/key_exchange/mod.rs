mod curve25519;
mod dh_group_sha1;

pub use self::curve25519::Curve25519;
pub use self::dh_group_sha1::DhGroupSha1;

use packet::Packet;

pub enum KeyExchangeResult {
    Ok(Option<Packet>),
    Done(Option<Packet>),
    Error(Option<Packet>),
}

pub trait KeyExchange {
    fn process(&mut self, packet: &Packet) -> KeyExchangeResult;
}
