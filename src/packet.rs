use std::fmt;
use std::str;
use parser;

pub struct Packet {
    pub payload: Vec<u8>,
    pub mac: Vec<u8>
}

impl Packet {
    pub fn parse(&self) {
        let result = parser::parse_packet(&self.payload.as_slice());
        println!("{:?}", result);
    }
}

impl fmt::Debug for Packet {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Packet({} bytes)", self.payload.len())
    }
}
