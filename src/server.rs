use std::net::TcpListener;
use std::io::{self, Write};

use session::{Session, SessionType};
use packet::Packet;
use protocol;

pub struct ServerConfig {
    pub host: String,
    pub port: u16,
}

impl Default for ServerConfig {
    fn default() -> ServerConfig {
        ServerConfig {
            host: "0.0.0.0".to_owned(),
            port: 22,
        }
    }
}

pub struct Server {
    config: ServerConfig,
}

impl Server {
    pub fn with_config(config: ServerConfig) -> Server {
        Server { config: config }
    }

    pub fn run(&self) -> io::Result<()> {
        let listener = TcpListener::bind((&*self.config.host, self.config.port)).expect(&*format!(
            "sshd: failed to bind to {}:{}",
            self.config.host,
            self.config.port
        ));
        let (mut stream, addr) = listener.accept().expect(&*format!(
            "sshd: failed to establish incoming connection"
        ));

        println!("Incoming connection from {}", addr);

        let id = protocol::read_identification(&mut stream)?;
        println!("{} identifies as {}", addr, id);

        protocol::send_identification(&mut stream)?;

        let mut session = Session::new(SessionType::Server, stream.try_clone().unwrap());

        loop {
            let packet = Packet::read_from(&mut stream).unwrap();
            println!("packet: {:?}", packet);
            session.process(&packet);

            use rand::{OsRng, Rng};
            let mut rng = OsRng::new()?;

            /*
            if message.msg_type() == MessageType::KexInit {
xs               let cookie: Vec<u8> = rng.gen_iter::<u8>().take(16).collect();
                let kex = message::kex::KeyExchangeInit {
                    cookie: cookie,
                    kex_algorithms: vec![message::kex::KeyExchangeAlgorithm::CURVE25519_SHA256],
                    server_host_key_algorithms: vec![message::kex::HostKeyAlgorithm::SSH_ED25519],
                    encryption_algorithms_client_to_server: vec![message::kex::EncryptionAlgorithm::AES256_CTR],
                    encryption_algorithms_server_to_client: vec![message::kex::EncryptionAlgorithm::AES256_CTR],
                    mac_algorithms_client_to_server: vec![message::kex::MacAlgorithm::HMAC_SHA2_512],
                    mac_algorithms_server_to_client: vec![message::kex::MacAlgorithm::HMAC_SHA2_512],
                    compression_algorithms_client_to_server: vec![message::kex::CompressionAlgorithm::None],
                    compression_algorithms_server_to_client: vec![message::kex::CompressionAlgorithm::None],
                    languages_client_to_server: vec![],
                    languages_server_to_client: vec![],
                    first_kex_packet_follows: false
                };
                protocol::write_message(&mut stream, &kex);
            }
            else {
                println!("Unhandled Message Type");
            }
            */
        }
        Ok(())
    }
}
