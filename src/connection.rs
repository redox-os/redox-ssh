use std::borrow::BorrowMut;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::sync::Arc;

use encryption::{AesCtr, Decryptor, Encryption};
use error::{ConnectionError, ConnectionResult};
use key_exchange::{self, KexResult, KeyExchange};
use message::MessageType;
use packet::{Packet, ReadPacketExt, WritePacketExt};
use server::ServerConfig;

#[derive(PartialEq)]
enum ConnectionState {
    Initial,
    KeyExchange,
    Established,
}

#[derive(Clone)]
pub enum ConnectionType {
    Server(Arc<ServerConfig>),
    Client,
}

#[derive(Default, Debug)]
pub struct HashData {
    pub client_id: Option<String>,
    pub server_id: Option<String>,
    pub client_kexinit: Option<Vec<u8>>,
    pub server_kexinit: Option<Vec<u8>>,
}

pub struct Connection {
    pub conn_type: ConnectionType,
    pub hash_data: HashData,
    state: ConnectionState,
    key_exchange: Option<Box<KeyExchange>>,
    stream: Box<Write>,
    session_id: Option<Vec<u8>>,
    encryption: Option<(Box<Encryption>, Box<Encryption>)>,
}

impl<'a> Connection {
    pub fn new(conn_type: ConnectionType, stream: Box<Write>) -> Connection {
        Connection {
            conn_type: conn_type,
            hash_data: HashData::default(),
            state: ConnectionState::Initial,
            key_exchange: None,
            stream: Box::new(stream),
            session_id: None,
            encryption: None,
        }
    }

    pub fn run(&mut self, stream: &mut Read) -> ConnectionResult<()> {
        let mut reader = BufReader::new(stream);

        self.send_id()?;
        self.read_id(&mut reader)?;

        loop {
            let packet = if let Some((ref mut c2s, _)) = self.encryption {
                println!("decrypting!!!");
                let mut decryptor = Decryptor::new(&mut **c2s, &mut reader);
                Packet::read_from(&mut decryptor)?
            }
            else {
                Packet::read_from(&mut reader)?
            };
            trace!("Packet received: {:?}", packet);
            self.process(packet)?;
        }
    }

    pub fn send(&mut self, packet: &Packet) -> io::Result<()> {
        packet.write_to(&mut self.stream)
    }

    fn send_id(&mut self) -> io::Result<()> {
        let id = format!("SSH-2.0-RedoxSSH_{}", env!("CARGO_PKG_VERSION"));
        info!("Identifying as {:?}", id);

        self.stream.write(id.as_bytes())?;
        self.stream.write(b"\r\n")?;
        self.stream.flush()?;

        self.hash_data.server_id = Some(id);

        Ok(())
    }

    fn read_id(&mut self, mut reader: &mut BufRead) -> io::Result<()> {
        // The identification string has a maximum length of 255 bytes
        // TODO: Make sure to stop reading if the client sends too much

        let mut id = String::new();

        while !id.starts_with("SSH-") {
            reader.read_line(&mut id)?;
        }

        let peer_id = id.trim_right().to_owned();
        info!("Peer identifies as {:?}", peer_id);
        self.hash_data.client_id = Some(peer_id);

        Ok(())
    }

    fn generate_key(&mut self, id: &[u8], len: usize)
        -> ConnectionResult<Vec<u8>> {
        use self::ConnectionError::KeyGenerationError;

        let kex = self.key_exchange.take().ok_or(KeyGenerationError)?;

        let key = kex.hash(
            &[
                kex.shared_secret().ok_or(KeyGenerationError)?,
                kex.exchange_hash().ok_or(KeyGenerationError)?,
                id,
                self.session_id
                    .as_ref()
                    .ok_or(KeyGenerationError)?
                    .as_slice(),
            ],
        );

        self.key_exchange = Some(kex);

        Ok(key)
    }

    pub fn process(&mut self, packet: Packet) -> ConnectionResult<()> {
        match packet.msg_type()
        {
            MessageType::KexInit => {
                println!("Starting Key Exchange!");
                self.kex_init(packet)
            }
            MessageType::NewKeys => {
                println!("Switching to new Keys");

                let iv_c2s = self.generate_key(b"A", 256)?;
                let iv_s2c = self.generate_key(b"B", 256)?;
                let enc_c2s = self.generate_key(b"C", 256)?;
                let enc_s2c = self.generate_key(b"D", 256)?;
                let int_c2s = self.generate_key(b"E", 256)?;
                let int_s2c = self.generate_key(b"F", 256)?;

                self.encryption =
                    Some((
                        Box::new(
                            AesCtr::new(enc_c2s.as_slice(), iv_c2s.as_slice()),
                        ),
                        Box::new(
                            AesCtr::new(enc_s2c.as_slice(), iv_s2c.as_slice()),
                        ),
                    ));

                Ok(())
            }
            MessageType::KeyExchange(_) => {
                let mut kex = self.key_exchange.take().ok_or(
                    ConnectionError::KeyExchangeError,
                )?;

                match kex.process(self, packet)
                {
                    KexResult::Done(packet) => {
                        self.state = ConnectionState::Established;
                        self.send(&packet)?;

                        if self.session_id.is_none() {
                            self.session_id =
                                kex.exchange_hash().map(|h| h.to_vec());
                        }

                        let packet = Packet::new(MessageType::NewKeys);
                        self.send(&packet)?;
                        Ok(())
                    }
                    KexResult::Ok(packet) => {
                        self.send(&packet)?;
                        Ok(())
                    }
                    KexResult::Error => Err(ConnectionError::KeyExchangeError),
                }?;

                self.key_exchange = Some(kex);
                Ok(())
            }
            _ => {
                println!("Unhandled packet: {:?}", packet);
                Err(ConnectionError::KeyExchangeError)
            }
        }
    }

    pub fn kex_init(&mut self, packet: Packet) -> ConnectionResult<()> {
        use algorithm::*;
        {
            let mut reader = packet.reader();
            let _ = reader.read_bytes(16)?; // Cookie. Throw it away.
            let kex_algos = reader.read_enum_list::<KeyExchangeAlgorithm>()?;
            let srv_host_key_algos =
                reader.read_enum_list::<PublicKeyAlgorithm>()?;
            let enc_algos_c2s = reader.read_enum_list::<EncryptionAlgorithm>()?;
            let enc_algos_s2c = reader.read_enum_list::<EncryptionAlgorithm>()?;
            let mac_algos_c2s = reader.read_enum_list::<MacAlgorithm>()?;
            let mac_algos_s2c = reader.read_enum_list::<MacAlgorithm>()?;
            let comp_algos_c2s = reader
                .read_enum_list::<CompressionAlgorithm>()?;
            let comp_algos_s2c = reader
                .read_enum_list::<CompressionAlgorithm>()?;

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
        }

        // Save payload for hash generation
        self.hash_data.client_kexinit = Some(packet.payload());

        // Create a random 16 byte cookie
        use rand::{self, Rng};
        let mut rng = rand::thread_rng();
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

        // Save payload for hash generation
        self.hash_data.server_kexinit = Some(packet.payload());

        Ok(())
    }
}
