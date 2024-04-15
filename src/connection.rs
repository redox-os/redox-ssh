use std::collections::{BTreeMap, VecDeque};
use std::io::{self, BufReader, Read, Write};
use std::sync::Arc;

use channel::{Channel, ChannelId, ChannelRequest};
use encryption::{AesCtr, Decryptor, Encryption};
use error::{ConnectionError, ConnectionResult as Result};
use key_exchange::{KexResult, KeyExchange};
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
    session_id: Option<Vec<u8>>,
    encryption: Option<(Box<Encryption>, Box<Encryption>)>,
    mac: Option<(Box<MacAlgorithm>, Box<MacAlgorithm>)>,
    seq: (u32, u32),
    tx_queue: VecDeque<Packet>,
    channels: BTreeMap<ChannelId, Channel>,
}

impl<'a> Connection {
    pub fn new(conn_type: ConnectionType) -> Connection {
        Connection {
            conn_type: conn_type,
            hash_data: HashData::default(),
            state: ConnectionState::Initial,
            key_exchange: None,
            session_id: None,
            encryption: None,
            mac: None,
            seq: (0, 0),
            tx_queue: VecDeque::new(),
            channels: BTreeMap::new(),
        }
    }

    pub fn run<S: Read + Write>(&mut self, stream: &mut S) -> Result<()> {
        self.send_id(stream)?;
        self.read_id(stream)?;

        let mut reader = BufReader::new(stream);

        loop {
            let packet = self.recv(&mut reader)?;
            let response = self.process(packet)?;

            let mut stream = reader.get_mut();

            if let Some(packet) = response {
                self.send(&mut stream, packet)?;
            }

            // Send additional packets from the queue
            let mut packets: Vec<Packet> = self.tx_queue.drain(..).collect();
            for packet in packets.drain(..) {
                self.send(&mut stream, packet)?;
            }
        }
    }

    fn recv(&mut self, mut stream: &mut Read) -> Result<Packet> {
        let packet = if let Some((ref mut c2s, _)) = self.encryption {
            let mut decryptor = Decryptor::new(&mut **c2s, &mut stream);
            Packet::read_from(&mut decryptor)?
        }
        else {
            Packet::read_from(&mut stream)?
        };

        if let Some((ref mut mac, _)) = self.mac {
            let mut sig = vec![0; mac.size()];
            stream.read_exact(&mut sig)?;

            let mut sig_cmp = vec![0; mac.size()];
            mac.sign(packet.data(), self.seq.0, sig_cmp.as_mut_slice());

            if sig != sig_cmp {
                return Err(ConnectionError::IntegrityError);
            }
        }

        debug!("Packet {} received: {:?}", self.seq.0, packet);

        // Count up the received packet sequence number
        self.seq.0 = self.seq.0.wrapping_add(1);

        Ok(packet)
    }

    fn send(&mut self, mut stream: &mut Write, packet: Packet)
        -> io::Result<()> {
        debug!("Sending packet {}: {:?}", self.seq.1, packet);

        let packet = packet.to_raw()?;

        if let Some((_, ref mut s2c)) = self.encryption {
            let mut encrypted = vec![0; packet.data().len()];
            s2c.encrypt(packet.data(), encrypted.as_mut_slice());

            // Sending encrypted packet
            stream.write_all(encrypted.as_slice())?;
        }
        else {
            packet.write_to(&mut stream)?;
        }

        if let Some((_, ref mut mac)) = self.mac {
            let mut sig = vec![0; mac.size()];
            mac.sign(packet.data(), self.seq.1, sig.as_mut_slice());
            stream.write_all(sig.as_slice())?;
        }

        self.seq.1 = self.seq.1.wrapping_add(1);

        Ok(())
    }

    fn send_id(&mut self, stream: &mut Write) -> io::Result<()> {
        let id = format!("SSH-2.0-RedoxSSH_{}", env!("CARGO_PKG_VERSION"));
        info!("Identifying as {:?}", id);

        stream.write(id.as_bytes())?;
        stream.write(b"\r\n")?;
        stream.flush()?;

        self.hash_data.server_id = Some(id);

        Ok(())
    }

    fn read_id(&mut self, stream: &mut Read) -> io::Result<()> {
        use std::str;

        let mut buf = [0; 255];
        let count = stream.read(&mut buf)?;

        let id = str::from_utf8(&buf[0..count]).map(str::trim).or(Err(
            io::Error::new(io::ErrorKind::InvalidData, "invalid id"),
        ))?;

        if id.starts_with("SSH-") {
            info!("Peer identifies as {:?}", id);
            self.hash_data.client_id = Some(id.to_owned());
            Ok(())
        }
        else {
            Err(io::Error::new(io::ErrorKind::InvalidData, "invalid id"))
        }
    }

    fn generate_key(&mut self, id: &[u8], len: usize) -> Result<Vec<u8>> {
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

    pub fn process(&mut self, packet: Packet) -> Result<Option<Packet>> {
        match packet.msg_type()
        {
            MessageType::KexInit => self.kex_init(packet),
            MessageType::NewKeys => self.new_keys(packet),
            MessageType::ServiceRequest => self.service_request(packet),
            MessageType::UserAuthRequest => self.user_auth_request(packet),
            MessageType::ChannelOpen => self.channel_open(packet),
            MessageType::ChannelRequest => self.channel_request(packet),
            MessageType::ChannelData => self.channel_data(packet),
            MessageType::KeyExchange(_) => self.key_exchange(packet),
            _ => {
                error!("Unhandled packet: {:?}", packet);
                Err(ConnectionError::ProtocolError)
            }
        }
    }

    fn new_keys(&mut self, packet: Packet) -> Result<Option<Packet>> {
        debug!("Switching to new keys");

        let iv_c2s = self.generate_key(b"A", 256)?;
        let iv_s2c = self.generate_key(b"B", 256)?;
        let enc_c2s = self.generate_key(b"C", 256)?;
        let enc_s2c = self.generate_key(b"D", 256)?;
        let mac_c2s = self.generate_key(b"E", 256)?;
        let mac_s2c = self.generate_key(b"F", 256)?;

        self.encryption =
            Some((
                Box::new(AesCtr::new(enc_c2s.as_slice(), iv_c2s.as_slice())),
                Box::new(AesCtr::new(enc_s2c.as_slice(), iv_s2c.as_slice())),
            ));

        self.mac = Some((
            Box::new(Hmac::new(mac_c2s.as_slice())),
            Box::new(Hmac::new(mac_s2c.as_slice())),
        ));

        Ok(None)
    }

    fn service_request(&mut self, packet: Packet) -> Result<Option<Packet>> {
        let mut reader = packet.reader();
        let name = reader.read_string()?;

        trace!(
            "Service Request {:?}",
            ::std::str::from_utf8(&name.as_slice()).unwrap()
        );

        let mut res = Packet::new(MessageType::ServiceAccept);
        res.write_bytes(name.as_slice())?;

        Ok(Some(res))
    }

    fn user_auth_request(&mut self, packet: Packet) -> Result<Option<Packet>> {
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

        debug!("User Auth {:?}, {:?}, {:?}", name, service, method);

        if success {
            Ok(Some(Packet::new(MessageType::UserAuthSuccess)))
        }
        else {
            let mut res = Packet::new(MessageType::UserAuthFailure);
            res.write_string("password")?;
            res.write_bool(false)?;

            Ok(Some(res))
        }
    }

    fn channel_open(&mut self, packet: Packet) -> Result<Option<Packet>> {
        let mut reader = packet.reader();
        let channel_type = reader.read_utf8()?;
        let peer_id = reader.read_uint32()?;
        let window_size = reader.read_uint32()?;
        let max_packet_size = reader.read_uint32()?;

        let id = if let Some((id, chan)) = self.channels.iter().next_back() {
            id + 1
        }
        else {
            0
        };

        let channel = Channel::new(id, peer_id, window_size, max_packet_size);

        let mut res = Packet::new(MessageType::ChannelOpenConfirmation);
        res.write_uint32(peer_id)?;
        res.write_uint32(channel.id())?;
        res.write_uint32(channel.window_size())?;
        res.write_uint32(channel.max_packet_size())?;

        debug!("Open {:?}", channel);

        self.channels.insert(id, channel);

        Ok(Some(res))
    }

    fn channel_request(&mut self, packet: Packet) -> Result<Option<Packet>> {
        let mut reader = packet.reader();
        let channel_id = reader.read_uint32()?;
        let name = reader.read_utf8()?;
        let want_reply = reader.read_bool()?;


        let request = match &*name
        {
            "pty-req" => Some(ChannelRequest::Pty {
                term: reader.read_utf8()?,
                chars: reader.read_uint32()? as u16,
                rows: reader.read_uint32()? as u16,
                pixel_width: reader.read_uint32()? as u16,
                pixel_height: reader.read_uint32()? as u16,
                modes: reader.read_string()?,
            }),
            "shell" => Some(ChannelRequest::Shell),
            _ => None,
        };


        if let Some(request) = request {
            let channel = self.channels.get_mut(&channel_id).unwrap();
            channel.request(request);
        }
        else {
            warn!("Unkown channel request {}", name);
        }

        if want_reply {
            let mut res = Packet::new(MessageType::ChannelSuccess);
            res.write_uint32(0)?;
            Ok(Some(res))
        }
        else {
            Ok(None)
        }
    }

    fn channel_data(&mut self, packet: Packet) -> Result<Option<Packet>> {
        let mut reader = packet.reader();
        let channel_id = reader.read_uint32()?;
        let data = reader.read_string()?;

        let channel = self.channels.get_mut(&channel_id).unwrap();
        channel.data(data.as_slice())?;

        Ok(None)
    }

    fn kex_init(&mut self, packet: Packet) -> Result<Option<Packet>> {
        use algorithm::*;

        let (kex_algo, srv_host_key_algo, enc_algo, mac_algo, comp_algo) = {
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

            (
                negotiate(KEY_EXCHANGE, kex_algos.as_slice())?,
                negotiate(HOST_KEY, srv_host_key_algos.as_slice())?,
                negotiate(ENCRYPTION, enc_algos_s2c.as_slice())?,
                negotiate(MAC, mac_algos_s2c.as_slice())?,
                negotiate(COMPRESSION, comp_algos_s2c.as_slice())?,
            )
        };

        debug!("Negotiated Kex Algorithm: {:?}", kex_algo);
        debug!("Negotiated Host Key Algorithm: {:?}", srv_host_key_algo);
        debug!("Negotiated Encryption Algorithm: {:?}", enc_algo);
        debug!("Negotiated Mac Algorithm: {:?}", mac_algo);
        debug!("Negotiated Comp Algorithm: {:?}", comp_algo);

        // Save payload for hash generation
        self.hash_data.client_kexinit = Some(packet.payload());

        // Create a random 16 byte cookie
        use rand::Rng;
        let mut rng = rand::thread_rng();
        let cookie: Vec<u8> = rng.gen_iter::<u8>().take(16).collect();

        let mut packet = Packet::new(MessageType::KexInit);
        packet.write_raw_bytes(cookie.as_slice())?;
        packet.write_list(KEY_EXCHANGE)?;
        packet.write_list(HOST_KEY)?;
        packet.write_list(ENCRYPTION)?;
        packet.write_list(ENCRYPTION)?;
        packet.write_list(MAC)?;
        packet.write_list(MAC)?;
        packet.write_list(COMPRESSION)?;
        packet.write_list(COMPRESSION)?;
        packet.write_string("")?;
        packet.write_string("")?;
        packet.write_bool(false)?;
        packet.write_uint32(0)?;

        self.state = ConnectionState::KeyExchange;
        self.key_exchange = kex_algo.instance();

        // Save payload for hash generation
        self.hash_data.server_kexinit = Some(packet.data().to_vec());

        Ok(Some(packet))
    }

    fn key_exchange(&mut self, packet: Packet) -> Result<Option<Packet>> {
        let mut kex = self.key_exchange.take().ok_or(
            ConnectionError::KeyExchangeError,
        )?;

        let result = match kex.process(self, packet)
        {
            KexResult::Done(packet) => {
                self.state = ConnectionState::Established;

                if self.session_id.is_none() {
                    self.session_id = kex.exchange_hash().map(|h| h.to_vec());
                }

                self.tx_queue.push_back(Packet::new(MessageType::NewKeys));

                Ok(Some(packet))
            }
            KexResult::Ok(packet) => Ok(Some(packet)),
            KexResult::Error => Err(ConnectionError::KeyExchangeError),
        };


        self.key_exchange = Some(kex);
        result
    }
}
