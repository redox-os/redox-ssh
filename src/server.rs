use std::io;
use std::net::TcpListener;
use std::sync::Arc;

use connection::{Connection, ConnectionType};
use public_key::KeyPair;

pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    pub key: Box<KeyPair>,
}

pub struct Server {
    config: Arc<ServerConfig>,
}

impl Server {
    pub fn with_config(config: ServerConfig) -> Server {
        Server { config: Arc::new(config) }
    }

    pub fn run(&self) -> io::Result<()> {
        let listener = TcpListener::bind(
            (&*self.config.host, self.config.port),
        ).expect(&*format!(
            "sshd: failed to bind to {}:{}",
            self.config.as_ref().host,
            self.config.as_ref().port
        ));

        loop {
            let (mut stream, addr) = listener.accept().expect(&*format!(
                "sshd: failed to establish incoming connection"
            ));

            println!("Incoming connection from {}", addr);

            let mut connection = Connection::new(
                ConnectionType::Server(self.config.clone()),
                Box::new(stream.try_clone().unwrap()),
            );

            let result = connection.run(&mut stream);
            if let Some(error) = result.err() {
                println!("sshd: {}", error)
            }
        }

        Ok(())
    }
}
