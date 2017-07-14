use std::io::{Read, Write, BufReader, BufRead};
use std::io;

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
