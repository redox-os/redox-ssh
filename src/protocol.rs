use std::io::{Read, Write, BufReader, BufRead};
use std::io;
use byteorder::{ReadBytesExt, BigEndian};

use packet::Packet;

pub fn send_identification<W: Write>(stream: &mut W) -> io::Result<usize> {
    let id = format!("SSH-2.0-RedoxSSH_{}\r\n", env!("CARGO_PKG_VERSION"));
    stream.write(id.as_bytes())
}

pub fn read_identification<R: Read>(stream: &mut R) -> io::Result<String> {
    // The identification string has a maximum length of 255 bytes
    // TODO: Make sure that we stop reading when the client sends more than that

    let mut reader = BufReader::new(stream);
    let mut id = String::new();

    while !id.starts_with("SSH-") {
        reader.read_line(&mut id)?;
    }

    Ok(id.trim_right().to_owned())
}

pub fn read_packet<R: Read>(stream: &mut R, mac_len: usize) -> io::Result<Packet> {
    let packet_len = stream.read_u32::<BigEndian>()? as usize;
    let padding_len = stream.read_u8()? as usize;
    let payload_len = packet_len - padding_len - 1;

    // TODO: Prevent packets that are too large

    let mut payload = Vec::with_capacity(payload_len);
    let mut padding = Vec::with_capacity(padding_len);
    let mut mac = Vec::with_capacity(mac_len);

    stream.take(payload_len as u64).read_to_end(&mut payload)?;
    stream.take(padding_len as u64).read_to_end(&mut padding)?;

    if mac_len > 0 {
        stream.take(mac_len as u64).read_to_end(&mut mac);
    }

    Ok(Packet { payload: payload, mac: mac })
}
