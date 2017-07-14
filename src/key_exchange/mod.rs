mod curve25519;

pub use self::curve25519::Curve25519;

use packet::Packet;

pub trait KeyExchange {
    fn process(&self, packet: &Packet);
}
