extern crate ssh;

use std::env;
use ssh::{Server, ServerConfig};

pub fn main() {
    let config = ServerConfig { host: String::from("0.0.0.0:22222") };
    let server = Server::with_config(config);
    server.start();
}
