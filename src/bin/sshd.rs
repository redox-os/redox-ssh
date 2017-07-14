#![cfg_attr(not(target_os = "redox"), feature(libc))]

extern crate ssh;

use std::io::{self, Write};
use std::str::FromStr;
use std::env;
use std::process;
use ssh::{Server, ServerConfig};

pub fn main() {
    let mut foreground = false;
    let mut quiet = false;

    let mut config = ServerConfig::default();

    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_ref() {
            "-f" => foreground = true,
            "-q" => quiet = true,
            "-p" => {
                config.port = u16::from_str(&args.next().expect("sshd: no argument to -p option"))
                    .expect("sshd: invalid port number to -p option");
            }
            _ => ()
        }
    }

    let server = Server::with_config(config);

    if !foreground && fork() != 0 {
        process::exit(0);
    }

    if let Err(err) = server.run() {
        writeln!(io::stderr(), "sshd: {}", err).unwrap();
        process::exit(1);
    }
}

#[cfg(target_os = "redox")]
fn fork()  -> usize {
    extern crate syscall;
    unsafe { syscall::clone(0).unwrap() }
}

#[cfg(not(target_os = "redox"))]
fn fork()  -> usize {
    extern crate libc;
    unsafe { libc::fork() as usize }
}
