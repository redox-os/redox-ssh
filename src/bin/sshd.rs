extern crate log;
extern crate ssh;

use std::env;
use std::fs::File;
use std::process;
use std::str::FromStr;

use log::{LevelFilter, Metadata, Record};

use ssh::public_key::ED25519;
use ssh::{Server, ServerConfig};

struct StdErrLogger;

impl log::Log for StdErrLogger {
    fn enabled(&self, _: &Metadata) -> bool {
        true
    }

    fn log(&self, record: &Record) {
        if self.enabled(record.metadata()) {
            eprintln!("{} - {}", record.level(), record.args());
        }
    }

    fn flush(&self) {
        todo!()
    }
}

pub fn main() {
    let mut verbosity = LevelFilter::Warn;
    let mut foreground = false;

    let key_pair =
        File::open("server.key").and_then(|mut f| (ED25519.import)(&mut f));

    if let Some(ref err) = key_pair.as_ref().err() {
        eprintln!("sshd: failed to open server.key: {}", err);
        process::exit(1);
    }

    let mut config = ServerConfig {
        host: String::from("0.0.0.0"),
        port: 22,
        key: key_pair.unwrap(),
    };

    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_ref() {
            "-v" => verbosity = LevelFilter::Info,
            "-vv" => verbosity = LevelFilter::Debug,
            "-vvv" => verbosity = LevelFilter::Trace,
            "-f" => foreground = true,
            "-p" => {
                config.port = u16::from_str(
                    &args.next().expect("sshd: no argument to -p option"),
                )
                .expect("sshd: invalid port number to -p option");
            }
            _ => (),
        }
    }

    log::set_logger(&StdErrLogger).unwrap();
    log::set_max_level(verbosity);

    if !foreground {
        use ssh::sys::fork;
        if fork() != 0 {
            process::exit(0);
        }
    }

    let server = Server::with_config(config);

    if let Err(err) = server.run() {
        eprintln!("sshd: {}", err);
        process::exit(1);
    }
}
