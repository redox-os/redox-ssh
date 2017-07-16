use std::io::{self, BufRead, BufReader, Read, Write};

use error::{ConnectionError, ConnectionResult};
use key_exchange::{self, KeyExchange, KeyExchangeResult};
use message::MessageType;
use packet::{Packet, ReadPacketExt, WritePacketExt};

#[derive(PartialEq)]
enum ConnectionState {
    Initial,
    KeyExchange,
    Established,
}

#[derive(PartialEq)]
pub enum ConnectionType {
    Server,
    Client,
}

pub struct Connection<W: Write> {
    ctype: ConnectionType,
    state: ConnectionState,
    key_exchange: Option<Box<KeyExchange>>,
    stream: W,
    my_id: String,
    peer_id: Option<String>,
}

impl<W: Write> Connection<W> {
    pub fn new(ctype: ConnectionType, stream: W) -> Connection<W> {
        Connection {
            ctype: ctype,
            state: ConnectionState::Initial,
            key_exchange: None,
            stream: stream,
            my_id: format!(
                "SSH-2.0-RedoxSSH_{}\r\n",
                env!("CARGO_PKG_VERSION")
            ),
            peer_id: None,
        }
    }

    pub fn run(&mut self, mut stream: &mut Read) -> ConnectionResult<()> {
        self.stream.write(self.my_id.as_bytes())?;
        self.stream.flush()?;

        self.peer_id = Some(self.read_id(stream)?);

        if let Some(ref peer_id) = self.peer_id {
            println!("Identifies as {:?}", peer_id);
        }

        loop {
            let packet = Packet::read_from(&mut stream)?;
            println!("packet: {:?}", packet);
            self.process(&packet);
        }
    }

    fn read_id(&mut self, stream: &mut Read) -> io::Result<String> {
        // The identification string has a maximum length of 255 bytes
        // TODO: Make sure to stop reading if the client sends too much

        let mut reader = BufReader::new(stream);
        let mut id = String::new();

        while !id.starts_with("SSH-") {
            reader.read_line(&mut id)?;
        }

        Ok(id.trim_right().to_owned())
    }

    pub fn process(&mut self, packet: &Packet) -> ConnectionResult<()> {
        match packet.msg_type()
        {
            MessageType::KexInit => {
                println!("Starting Key Exchange!");
                self.kex_init(packet)
            }
            MessageType::KeyExchange(_) => {
                let ref mut kex = self.key_exchange.as_mut().ok_or(
                    ConnectionError::KeyExchangeError,
                )?;

                match kex.process(packet)
                {
                    KeyExchangeResult::Ok(Some(packet)) => {
                        packet.write_to(&mut self.stream)?;
                    }
                    KeyExchangeResult::Error(Some(packet)) => {
                        packet.write_to(&mut self.stream)?;
                    }
                    KeyExchangeResult::Done(packet) => {
                        if let Some(packet) = packet {
                            packet.write_to(&mut self.stream)?;
                        }
                        self.state = ConnectionState::Established;
                    }
                    KeyExchangeResult::Ok(None) |
                    KeyExchangeResult::Error(None) => {}
                };
                Ok(())
            }
            _ => {
                println!("Unhandled packet: {:?}", packet);
                Err(ConnectionError::KeyExchangeError)
            }
        }
    }

    pub fn kex_init(&mut self, packet: &Packet) -> ConnectionResult<()> {
        use algorithm::*;
        let mut reader = packet.reader();

        let _ = reader.read_bytes(16)?; // Cookie. Throw it away.
        let kex_algos = reader.read_enum_list::<KeyExchangeAlgorithm>()?;
        let srv_host_key_algos = reader.read_enum_list::<PublicKeyAlgorithm>()?;
        let enc_algos_c2s = reader.read_enum_list::<EncryptionAlgorithm>()?;
        let enc_algos_s2c = reader.read_enum_list::<EncryptionAlgorithm>()?;
        let mac_algos_c2s = reader.read_enum_list::<MacAlgorithm>()?;
        let mac_algos_s2c = reader.read_enum_list::<MacAlgorithm>()?;
        let comp_algos_c2s = reader.read_enum_list::<CompressionAlgorithm>()?;
        let comp_algos_s2c = reader.read_enum_list::<CompressionAlgorithm>()?;

        let kex_algo = negotiate(KEY_EXCHANGE, kex_algos.as_slice())?;
        let srv_host_key_algo =
            negotiate(HOST_KEY, srv_host_key_algos.as_slice())?;
        let enc_algo = negotiate(ENCRYPTION, enc_algos_s2c.as_slice())?;
        let mac_algo = negotiate(MAC, mac_algos_s2c.as_slice())?;
        let comp_algo = negotiate(COMPRESSION, comp_algos_s2c.as_slice())?;

        println!("Negotiated Kex Algorithm: {:?}", kex_algo);
        println!("Negotiated Host Key Algorithm: {:?}", srv_host_key_algo);
        println!("Negotiated Encryption Algorithm: {:?}", enc_algo);
        println!("Negotiated Mac Algorithm: {:?}", mac_algo);
        println!("Negotiated Comp Algorithm: {:?}", comp_algo);

        use rand::{OsRng, Rng};
        let mut rng = OsRng::new()?;
        let cookie: Vec<u8> = rng.gen_iter::<u8>().take(16).collect();

        let mut packet = Packet::new(MessageType::KexInit);
        packet.with_writer(&|w| {
            w.write_raw_bytes(cookie.as_slice())?;
            w.write_list(KEY_EXCHANGE)?;
            w.write_list(HOST_KEY)?;
            w.write_list(ENCRYPTION)?;
            w.write_list(ENCRYPTION)?;
            w.write_list(MAC)?;
            w.write_list(MAC)?;
            w.write_list(COMPRESSION)?;
            w.write_list(COMPRESSION)?;
            w.write_string("")?;
            w.write_string("")?;
            w.write_bool(false)?;
            w.write_uint32(0)?;
            Ok(())
        })?;

        self.state = ConnectionState::KeyExchange;
        self.key_exchange = Some(Box::new(key_exchange::Curve25519::new()));
        packet.write_to(&mut self.stream)?;
        Ok(())
    }
}
