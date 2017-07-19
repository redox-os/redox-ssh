use std::io;
use std::net::TcpListener;
use std::sync::Arc;
use std::thread;

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
        let listener =
            TcpListener::bind((&*self.config.host, self.config.port))?;

        loop {
            let (stream, addr) = listener.accept()?;
            let config = self.config.clone();

            debug!("Incoming connection from {}", addr);

            thread::spawn(move || {
                let mut read_stream = stream.try_clone().unwrap();

                let mut connection = Connection::new(
                    ConnectionType::Server(config),
                    Box::new(stream),
                );

                let result = connection.run(&mut read_stream);

                if let Some(error) = result.err() {
                    println!("sshd: {}", error)
                }
            });
        }

        Ok(())
    }
}
