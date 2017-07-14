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
        protocol::send_identification(&mut stream)?;

        let id = protocol::read_identification(&mut stream)?;
        println!("{} identifies as {}", addr, id);

        let mut session = Session::new(SessionType::Server, stream.try_clone().unwrap());

        loop {
            let packet = Packet::read_from(&mut stream).unwrap();
            println!("packet: {:?}", packet);
            session.process(&packet);
        }
        Ok(())
    }
}
