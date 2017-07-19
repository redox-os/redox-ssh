mod curve25519;
// mod dh_group_sha1;

pub use self::curve25519::Curve25519;
// pub use self::dh_group_sha1::DhGroupSha1;

use connection::Connection;
use packet::Packet;

pub enum KexResult {
    Ok(Packet),
    Done(Packet),
    Error,
}

pub trait KeyExchange {
    fn process(&mut self, conn: &mut Connection, packet: Packet) -> KexResult;
    fn shared_secret<'a>(&'a self) -> Option<&'a [u8]>;
    fn exchange_hash<'a>(&'a self) -> Option<&'a [u8]>;
    fn hash(&self, data: &[&[u8]]) -> Vec<u8>;
}
