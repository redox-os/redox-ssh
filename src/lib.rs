extern crate byteorder;
extern crate rand;
extern crate crypto;
extern crate num_bigint;
#[macro_use]
extern crate log;
#[cfg(target_os = "redox")]
extern crate syscall;
#[cfg(not(target_os = "redox"))]
extern crate libc;

mod packet;
mod message;
mod connection;
mod key_exchange;
mod encryption;
mod mac;
mod channel;

pub mod error;
pub mod algorithm;
pub mod public_key;
pub mod server;

pub use self::server::{Server, ServerConfig};

#[cfg(target_os = "redox")]
#[path = "sys/redox/mod.rs"]
pub mod sys;

#[cfg(not(target_os = "redox"))]
#[path = "sys/linux/mod.rs"]
pub mod sys;
