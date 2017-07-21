use connection::{Connection, ConnectionType};
use crypto::curve25519;
use crypto::digest::Digest;
use crypto::sha2::Sha256;
use key_exchange::{KexResult, KeyExchange};
use message::MessageType;
use num_bigint::{BigInt, Sign};
use packet::{Packet, ReadPacketExt, WritePacketExt};
use rand::{self, Rng};

const ECDH_KEX_INIT: u8 = 30;
const ECDH_KEX_REPLY: u8 = 31;

pub struct Curve25519 {
    shared_secret: Option<Vec<u8>>,
    exchange_hash: Option<Vec<u8>>,
}

impl Curve25519 {
    pub fn new() -> Curve25519 {
        Curve25519 {
            shared_secret: None,
            exchange_hash: None,
        }
    }
}

impl KeyExchange for Curve25519 {
    fn shared_secret<'a>(&'a self) -> Option<&'a [u8]> {
        self.shared_secret.as_ref().map(|x| x as &[u8])
    }

    fn exchange_hash<'a>(&'a self) -> Option<&'a [u8]> {
        self.exchange_hash.as_ref().map(|x| x.as_slice())
    }

    fn hash(&self, data: &[&[u8]]) -> Vec<u8> {
        let mut hash = [0; 32];
        let mut hasher = Sha256::new();

        for item in data {
            hasher.input(item);
        }

        hasher.result(&mut hash);
        hash.to_vec()
    }

    fn process(&mut self, conn: &mut Connection, packet: Packet) -> KexResult {
        match packet.msg_type()
        {
            MessageType::KeyExchange(ECDH_KEX_INIT) => {
                let mut reader = packet.reader();
                let client_public = reader.read_string().unwrap();

                let config = match &conn.conn_type
                {
                    &ConnectionType::Server(ref config) => config.clone(),
                    _ => return KexResult::Error,
                };

                let public_key = {
                    let mut key = Vec::new();
                    config.as_ref().key.write_public(&mut key).unwrap();
                    key
                };

                let mut packet =
                    Packet::new(MessageType::KeyExchange(ECDH_KEX_REPLY));

                let server_secret = {
                    let mut secret = [0; 32];
                    let mut rng = rand::thread_rng();
                    rng.fill_bytes(&mut secret);

                    secret[0] &= 248;
                    secret[31] &= 127;
                    secret[31] |= 64;

                    secret
                };

                let server_public = curve25519::curve25519_base(&server_secret);
                let shared_secret = {
                    let mut buf = Vec::new();
                    buf.write_mpint(BigInt::from_bytes_be(
                        Sign::Plus,
                        &curve25519::curve25519(&server_secret, &client_public),
                    )).ok();
                    buf
                };

                let hash_data = {
                    let mut buf = Vec::new();
                    let data = &conn.hash_data;

                    let items =
                        [
                            data.client_id.as_ref().unwrap().as_bytes(),
                            data.server_id.as_ref().unwrap().as_bytes(),
                            data.client_kexinit.as_ref().unwrap().as_slice(),
                            data.server_kexinit.as_ref().unwrap().as_slice(),
                            public_key.as_slice(),
                            client_public.as_slice(),
                            &server_public,
                        ];

                    for item in items.iter() {
                        buf.write_bytes(item).ok();
                    }

                    buf.write_raw_bytes(&shared_secret).ok();

                    buf
                };

                // Calculate hash
                let hash = self.hash(&[hash_data.as_slice()]);
                let signature = config.as_ref().key.sign(&hash).unwrap();

                packet.write_bytes(public_key.as_slice()).unwrap();
                packet.write_bytes(&server_public).unwrap();
                packet.write_bytes(signature.as_slice()).unwrap(); // Signature

                self.exchange_hash = Some(hash);
                self.shared_secret = Some(shared_secret);

                KexResult::Done(packet)
            }
            _ => {
                debug!("Unhandled key exchange packet: {:?}", packet);
                KexResult::Error
            }
        }
    }
}
