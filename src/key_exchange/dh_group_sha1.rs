use key_exchange::{KeyExchange, KeyExchangeResult};
use message::MessageType;
use num_bigint::{BigInt, RandBigInt, ToBigInt};
use packet::{Packet, ReadPacketExt, WritePacketExt};
use rand;

const DH_GEX_GROUP: u8 = 31;
const DH_GEX_INIT: u8 = 32;
const DH_GEX_REPLY: u8 = 33;
const DH_GEX_REQUEST: u8 = 34;

/// Second Oakley Group
/// Source: https://tools.ietf.org/html/rfc2409#section-6.2
#[cfg_attr(rustfmt, rustfmt_skip)]
static OAKLEY_GROUP_2: &[u32] = &[
    0xFFFFFFFF, 0xFFFFFFFF, 0xC90FDAA2, 0x2168C234, 0xC4C6628B, 0x80DC1CD1,
    0x29024E08, 0x8A67CC74, 0x020BBEA6, 0x3B139B22, 0x514A0879, 0x8E3404DD,
    0xEF9519B3, 0xCD3A431B, 0x302B0A6D, 0xF25F1437, 0x4FE1356D, 0x6D51C245,
    0xE485B576, 0x625E7EC6, 0xF44C42E9, 0xA637ED6B, 0x0BFF5CB6, 0xF406B7ED,
    0xEE386BFB, 0x5A899FA5, 0xAE9F2411, 0x7C4B1FE6, 0x49286651, 0xECE65381,
    0xFFFFFFFF, 0xFFFFFFFF
];

pub struct DhGroupSha1 {
    g: Option<BigInt>,
    p: Option<BigInt>,
    e: Option<BigInt>,
}

impl DhGroupSha1 {
    pub fn new() -> DhGroupSha1 {
        DhGroupSha1 {
            g: None,
            p: None,
            e: None
        }
    }
}

impl KeyExchange for DhGroupSha1 {
    fn process(&mut self, packet: &Packet) -> KeyExchangeResult {
        match packet.msg_type() {
            MessageType::KeyExchange(DH_GEX_REQUEST) => {
                let mut reader = packet.reader();
                let min = reader.read_uint32().unwrap();
                let opt = reader.read_uint32().unwrap();
                let max = reader.read_uint32().unwrap();

                println!("Key Sizes: Min {}, Opt {}, Max {}", min, opt, max);

                let mut rng = rand::thread_rng();
                let g = rng.gen_biguint(opt as usize).to_bigint().unwrap();
                let p = rng.gen_biguint(opt as usize).to_bigint().unwrap();

                let mut packet = Packet::new(MessageType::KeyExchange(DH_GEX_GROUP));
                packet.with_writer(&|w| {
                    w.write_mpint(g.clone())?;
                    w.write_mpint(p.clone())?;
                    Ok(())
                });

                self.g = Some(g);
                self.p = Some(p);

                KeyExchangeResult::Ok(Some(packet))
            },
            MessageType::KeyExchange(DH_GEX_INIT) => {
                let mut reader = packet.reader();
                let e = reader.read_mpint().unwrap();

                println!("Received e: {:?}", e);

                let mut packet = Packet::new(MessageType::KeyExchange(DH_GEX_REPLY));
                packet.with_writer(&|w| {
                    w.write_string("HELLO WORLD")?;
                    w.write_mpint(e.clone())?;
                    w.write_string("HELLO WORLD")?;
                    Ok(())
                });

                self.e = Some(e);

                KeyExchangeResult::Ok(Some(packet))
            },
            _ => {
                debug!("Unhandled key exchange packet: {:?}", packet);
                KeyExchangeResult::Error(None)
            }
        }
    }
}
