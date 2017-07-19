use std::io::{self, BufRead, BufReader, Read, Write};
use std::sync::Arc;

use encryption::{AesCtr, Decryptor, Encryption};
use error::{ConnectionError, ConnectionResult};
use key_exchange::{self, KexResult, KeyExchange};
use mac::{Hmac, MacAlgorithm};
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
    mac: Option<(Box<MacAlgorithm>, Box<MacAlgorithm>)>,
    seq: (u32, u32),
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
            mac: None,
            seq: (0, 0),
        }
    }

    pub fn run(&mut self, stream: &mut Read) -> ConnectionResult<()> {
        let mut reader = BufReader::new(stream);

        self.send_id()?;
        self.read_id(&mut reader)?;

        loop {
            let packet = if let Some((ref mut c2s, _)) = self.encryption {
                let mut decryptor = Decryptor::new(&mut **c2s, &mut reader);
                Packet::read_from(&mut decryptor)?
            }
            else {
                Packet::read_from(&mut reader)?
            };

            if let Some((ref mut mac, _)) = self.mac {
                let mut sig = vec![0; mac.size()];
                reader.read_exact(&mut sig)?;

                let mut sig_cmp = vec![0; mac.size()];
                mac.sign(packet.data(), self.seq.0, sig_cmp.as_mut_slice());

                if sig != sig_cmp {
                    return Err(ConnectionError::IntegrityError);
                }
            }

            trace!("Packet {} received: {:?}", self.seq.0, packet);
            self.process(packet)?;

            self.seq.0 = self.seq.0.wrapping_add(1);
        }
    }

    pub fn send(&mut self, packet: Packet) -> io::Result<()> {
        trace!("Sending packet {}: {:?}", self.seq.1, packet);

        let packet = packet.to_raw()?;

        if let Some((_, ref mut s2c)) = self.encryption {

            let mut encrypted = vec![0; packet.data().len()];
            s2c.encrypt(packet.data(), encrypted.as_mut_slice());

            // Sending encrypted packet
            self.stream.write_all(encrypted.as_slice())?;
        }
        else {
            packet.write_to(&mut self.stream)?;
        }

        self.seq.1 = self.seq.1.wrapping_add(1);

        if let Some((_, ref mut mac)) = self.mac {
            let mut sig = vec![0; mac.size()];
            mac.sign(packet.data(), self.seq.1, sig.as_mut_slice());
            self.stream.write_all(sig.as_slice())?;
        }

        Ok(())
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
                debug!("Starting key exchange");
                self.kex_init(packet)
            }
            MessageType::NewKeys => {
                debug!("Switching to new keys");

                let iv_c2s = self.generate_key(b"A", 256)?;
                let iv_s2c = self.generate_key(b"B", 256)?;
                let enc_c2s = self.generate_key(b"C", 256)?;
                let enc_s2c = self.generate_key(b"D", 256)?;
                let mac_c2s = self.generate_key(b"E", 256)?;
                let mac_s2c = self.generate_key(b"F", 256)?;

                self.encryption =
                    Some((
                        Box::new(
                            AesCtr::new(enc_c2s.as_slice(), iv_c2s.as_slice()),
                        ),
                        Box::new(
                            AesCtr::new(enc_s2c.as_slice(), iv_s2c.as_slice()),
                        ),
                    ));

                self.mac = Some((
                    Box::new(Hmac::new(mac_c2s.as_slice())),
                    Box::new(Hmac::new(mac_s2c.as_slice())),
                ));

                Ok(())
            }
            MessageType::ServiceRequest => {
                let mut reader = packet.reader();
                let name = reader.read_string()?;

                trace!(
                    "{:?}",
                    ::std::str::from_utf8(&name.as_slice()).unwrap()
                );

                let mut res = Packet::new(MessageType::ServiceAccept);
                res.with_writer(&|w| {
                    w.write_bytes(name.as_slice())?;
                    Ok(())
                })?;

                self.send(res)?;
                Ok(())
            }
            MessageType::UserAuthRequest => {
                let mut reader = packet.reader();
                let name = reader.read_utf8()?;
                let service = reader.read_utf8()?;
                let method = reader.read_utf8()?;

                let success = if method == "password" {
                    assert!(reader.read_bool()? == false);
                    let pass = reader.read_utf8()?;
                    pass == "hunter2"
                }
                else {
                    false
                };

                if success {
                    self.send(Packet::new(MessageType::UserAuthSuccess))?;
                }
                else {
                    let mut res = Packet::new(MessageType::UserAuthFailure);
                    res.with_writer(&|w| {
                        w.write_string("password")?;
                        w.write_bool(false)?;
                        Ok(())
                    })?;

                    self.send(res)?;
                }

                debug!("User Auth {:?}, {:?}, {:?}", name, service, method);
                Ok(())
            }
            MessageType::ChannelOpen => {
                let mut reader = packet.reader();
                let channel_type = reader.read_utf8()?;
                let sender_channel = reader.read_uint32()?;
                let window_size = reader.read_uint32()?;
                let max_packet_size = reader.read_uint32()?;

                let mut res = Packet::new(MessageType::ChannelOpenConfirmation);
                res.with_writer(&|w| {
                    w.write_uint32(sender_channel)?;
                    w.write_uint32(0)?;
                    w.write_uint32(window_size)?;
                    w.write_uint32(max_packet_size)?;
                    Ok(())
                })?;

                self.send(res)?;
                debug!(
                    "Channel Open {:?}, {:?}, {:?}, {:?}",
                    channel_type,
                    sender_channel,
                    window_size,
                    max_packet_size
                );

                Ok(())
            }
            MessageType::ChannelRequest => {
                let mut reader = packet.reader();
                let channel = reader.read_uint32()?;
                let request = reader.read_utf8()?;
                let want_reply = reader.read_bool()?;

                debug!(
                    "Channel Request {:?}, {:?}, {:?}",
                    channel,
                    request,
                    want_reply
                );

                if request == "pty-req" {
                    let term = reader.read_utf8()?;
                    let char_width = reader.read_uint32()?;
                    let row_height = reader.read_uint32()?;
                    let pixel_width = reader.read_uint32()?;
                    let pixel_height = reader.read_uint32()?;
                    let modes = reader.read_string()?;

                    debug!(
                        "PTY request: {:?} {:?} {:?} {:?} {:?} {:?}",
                        term,
                        char_width,
                        row_height,
                        pixel_width,
                        pixel_height,
                        modes
                    );
                }

                if request == "shell" {
                    debug!("Shell request");
                }

                if want_reply {
                    let mut res = Packet::new(MessageType::ChannelSuccess);
                    res.with_writer(&|w| w.write_uint32(0))?;
                    self.send(res)?;
                }

                Ok(())
            }
            MessageType::ChannelData => {
                let mut reader = packet.reader();
                let channel = reader.read_uint32()?;
                let data = reader.read_string()?;

                let mut res = Packet::new(MessageType::ChannelData);
                res.with_writer(&|w| {
                    w.write_uint32(0)?;
                    w.write_bytes(data.as_slice())?;
                    Ok(())
                })?;

                self.send(res)?;

                debug!(
                    "Channel {} Data ({} bytes): {:?}",
                    channel,
                    data.len(),
                    data
                );
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
                        self.send(packet)?;

                        if self.session_id.is_none() {
                            self.session_id =
                                kex.exchange_hash().map(|h| h.to_vec());
                        }

                        let packet = Packet::new(MessageType::NewKeys);
                        self.send(packet)?;
                        Ok(())
                    }
                    KexResult::Ok(packet) => {
                        self.send(packet)?;
                        Ok(())
                    }
                    KexResult::Error => Err(ConnectionError::KeyExchangeError),
                }?;

                self.key_exchange = Some(kex);
                Ok(())
            }
            _ => {
                error!("Unhandled packet: {:?}", packet);
                Err(ConnectionError::ProtocolError)
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

            debug!("Negotiated Kex Algorithm: {:?}", kex_algo);
            debug!("Negotiated Host Key Algorithm: {:?}", srv_host_key_algo);
            debug!("Negotiated Encryption Algorithm: {:?}", enc_algo);
            debug!("Negotiated Mac Algorithm: {:?}", mac_algo);
            debug!("Negotiated Comp Algorithm: {:?}", comp_algo);
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
