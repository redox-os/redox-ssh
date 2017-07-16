use std::io::{self, Write};
use std::net::TcpListener;

use connection::{Connection, ConnectionType};
use packet::Packet;
use public_key::KeyPair;

pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    pub key: Box<KeyPair>,
}

pub struct Server {
    config: ServerConfig,
}

impl Server {
    pub fn with_config(config: ServerConfig) -> Server {
        Server { config: config }
    }

    pub fn run(&self) -> io::Result<()> {
        let listener = TcpListener::bind(
            (&*self.config.host, self.config.port),
        ).expect(&*format!(
            "sshd: failed to bind to {}:{}",
            self.config.host,
            self.config.port
        ));

        loop {
            let (mut stream, addr) = listener.accept().expect(&*format!(
                "sshd: failed to establish incoming connection"
            ));

            println!("Incoming connection from {}", addr);

            let mut connection = Connection::new(
                ConnectionType::Server,
                stream.try_clone().unwrap(),
            );

            connection.run(&mut stream);
        }

        Ok(())
    }
}
