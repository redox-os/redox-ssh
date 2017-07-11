use std::net::TcpListener;
use std::io;

use protocol;

pub struct ServerConfig {
    pub host: String
}

pub struct Server {
    config: ServerConfig
}

impl Server {
    pub fn with_config(config: ServerConfig) -> Server {
        Server { config: config }
    }

    pub fn start(&self) -> io::Result<()> {
        let listener = TcpListener::bind(&*self.config.host)
            .expect(&*format!("Failed to bind to {}.", self.config.host));
        let (mut stream, addr) = listener.accept()
            .expect(&*format!("Failed to establish incomin connection."));

        println!("Connection established!");

        let id = protocol::read_identification(&mut stream)?;
        println!("Incoming connection from {}", id);

        protocol::send_identification(&mut stream)?;

        loop {
            let packet = protocol::read_packet(&mut stream, 0)?;
            let message = packet.parse();


            println!("{:?}", message);
        }
        Ok(())
    }
}
