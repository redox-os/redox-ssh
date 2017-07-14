use key_exchange::KeyExchange;
use message::MessageType;
use packet::{Packet, ReadPacketExt, WritePacketExt};
use std::io::Write;

#[derive(PartialEq)]
enum SessionState {
    Initial,
    KeyExchange,
    Established
}

#[derive(PartialEq)]
pub enum SessionType {
    Server,
    Client
}

pub struct Session<'a, W: Write> {
    stype: SessionType,
    state: SessionState,
    key_exchange: Option<&'a KeyExchange>,
    stream: W
}

impl<'a, W: Write> Session<'a, W> {
    pub fn new(stype: SessionType, stream: W) -> Session<'a, W> {
        Session {
            stype: stype,
            state: SessionState::Initial,
            key_exchange: None,
            stream: stream
        }
    }

    pub fn process(&mut self, packet: &Packet) {
        match packet.msg_type() {
            MessageType::KexInit => {
                println!("Starting Key Exchange!");
                self.kex_init(packet);
            }
            _ => {
                println!("Unhandled packet: {:?}", packet);
            }
        }
    }

    pub fn kex_init(&mut self, packet: &Packet) {
        use algorithm::*;
        let mut reader = packet.reader();

        reader.read_msg_type();
        let cookie = reader.read_bytes(16);
        let kex_algos = reader.read_enum_list::<KeyExchangeAlgorithm>();
        let srv_host_key_algos = reader.read_enum_list::<PublicKeyAlgorithm>();
        let enc_algos_c2s = reader.read_enum_list::<EncryptionAlgorithm>();
        let enc_algos_s2c = reader.read_enum_list::<EncryptionAlgorithm>();
        let mac_algos_c2s = reader.read_enum_list::<MacAlgorithm>();
        let mac_algos_s2c = reader.read_enum_list::<MacAlgorithm>();
        let comp_algos_c2s = reader.read_enum_list::<CompressionAlgorithm>();
        let comp_algos_s2c = reader.read_enum_list::<CompressionAlgorithm>();

        let kex_algo = negotiate(KEY_EXCHANGE, kex_algos.unwrap().as_slice());
        let srv_host_key_algo = negotiate(HOST_KEY, srv_host_key_algos.unwrap().as_slice());
        let enc_algo = negotiate(ENCRYPTION, enc_algos_s2c.unwrap().as_slice());
        let mac_algo = negotiate(MAC, mac_algos_s2c.unwrap().as_slice());
        let comp_algo = negotiate(COMPRESSION, comp_algos_s2c.unwrap().as_slice());

        println!("Negociated Kex Algorithm: {:?}", kex_algo);
        println!("Negociated Host Key Algorithm: {:?}", srv_host_key_algo);
        println!("Negociated Encryption Algorithm: {:?}", enc_algo);
        println!("Negociated Mac Algorithm: {:?}", mac_algo);
        println!("Negociated Comp Algorithm: {:?}", comp_algo);

        use rand::{OsRng, Rng};
        let mut rng = OsRng::new().unwrap();
        let cookie: Vec<u8> = rng.gen_iter::<u8>().take(16).collect();

        let mut packet = Packet::new(MessageType::KexInit);
        packet.with_writer(&|w| {
            w.write_bytes(cookie.as_slice());
            w.write_list(KEY_EXCHANGE);
            w.write_list(HOST_KEY);
            w.write_list(ENCRYPTION);
            w.write_list(ENCRYPTION);
            w.write_list(MAC);
            w.write_list(MAC);
            w.write_list(COMPRESSION);
            w.write_list(COMPRESSION);
            w.write_string("");
            w.write_string("");
            w.write_bool(false);
            w.write_bytes(&[0, 0, 0, 0]);
        });

        self.state = SessionState::KeyExchange;
        packet.write_to(&mut self.stream);
    }
}
