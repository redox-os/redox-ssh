use crypto::curve25519::curve25519;
use key_exchange::{KeyExchange, KeyExchangeResult};
use message::MessageType;
use packet::{Packet, ReadPacketExt, WritePacketExt};
use public_key::ED25519;

const ECDH_KEX_INIT: u8 = 30;
const ECDH_KEX_REPLY: u8 = 31;

pub struct Curve25519 {}

impl Curve25519 {
    pub fn new() -> Curve25519 {
        Curve25519 {}
    }
}

impl KeyExchange for Curve25519 {
    fn process(&mut self, packet: &Packet) -> KeyExchangeResult {
        match packet.msg_type()
        {
            MessageType::KeyExchange(ECDH_KEX_INIT) => {
                let mut reader = packet.reader();
                let qc = reader.read_string().unwrap();

                let keypair = (ED25519.generate_key_pair)(None);
                let mut public_key = Vec::new();
                keypair.write_public(&mut public_key);

                println!("Received qc: {:?}", qc);
                let mut packet =
                    Packet::new(MessageType::KeyExchange(ECDH_KEX_REPLY));

                packet.with_writer(&|w| {
                    w.write_bytes(public_key.as_slice())?;
                    w.write_bytes(qc.as_slice())?;
                    w.write_bytes(&[0; 256])?;
                    Ok(())
                });

                KeyExchangeResult::Ok(Some(packet))
            }
            _ => {
                debug!("Unhandled key exchange packet: {:?}", packet);
                KeyExchangeResult::Error(None)
            }
        }
    }
}
