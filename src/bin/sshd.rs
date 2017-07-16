extern crate ssh;
extern crate log;

use std::env;
use std::fs::File;
use std::io::{self, Write};
use std::process;
use std::str::FromStr;

use log::{LogLevelFilter, LogMetadata, LogRecord};

use ssh::{Server, ServerConfig};
use ssh::public_key::ED25519;

struct StdErrLogger;

impl log::Log for StdErrLogger {
    fn enabled(&self, _: &LogMetadata) -> bool {
        true
    }

    fn log(&self, record: &LogRecord) {
        if self.enabled(record.metadata()) {
            writeln!(io::stderr(), "{} - {}", record.level(), record.args())
                .unwrap();
        }
    }
}

pub fn main() {
    let mut verbose = false;

    let key_pair = File::open("server.key").and_then(
        |mut f| (ED25519.import)(&mut f),
    );

    if let Some(ref err) = key_pair.as_ref().err() {
        writeln!(io::stderr(), "sshd: failed to open server.key: {}", err)
            .unwrap();
        process::exit(1);
    }

    let mut config = ServerConfig {
        host: String::from("0.0.0.0"),
        port: 22,
        key: key_pair.unwrap(),
    };

    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_ref()
        {
            "-v" => verbose = true,
            "-p" => {
                config.port =
                    u16::from_str(
                        &args.next().expect("sshd: no argument to -p option"),
                    ).expect("sshd: invalid port number to -p option");
            }
            _ => (),
        }
    }

    if verbose {
        log::set_logger(|max_log_level| {
            max_log_level.set(LogLevelFilter::Trace);
            Box::new(StdErrLogger)
        }).unwrap();
    }

    let server = Server::with_config(config);

    if let Err(err) = server.run() {
        writeln!(io::stderr(), "sshd: {}", err).unwrap();
        process::exit(1);
    }
}
