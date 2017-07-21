use std::fmt;
use std::io::{self, BufReader, Read, Result, Write};
use std::str::{self, FromStr};
use std::string::ToString;

use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};

use message::MessageType;
use num_bigint::BigInt;

pub enum Packet {
    Raw(Vec<u8>, usize),
    Payload(Vec<u8>),
}

impl Packet {
    pub fn new(msg_type: MessageType) -> Packet {
        Packet::Payload([msg_type.into()].to_vec())
    }

    pub fn msg_type(&self) -> MessageType {
        match self
        {
            &Packet::Raw(ref data, _) => data[5],
            &Packet::Payload(ref data) => data[0],
        }.into()
    }

    pub fn read_from<R: io::Read>(stream: &mut R) -> Result<Packet> {
        let packet_len = stream.read_uint32()? as usize;
        trace!("Reading incoming packet ({} bytes)", packet_len);

        // TODO: Prevent packets that are too large

        let mut raw = Vec::with_capacity(packet_len + 4);
        raw.write_uint32(packet_len as u32)?;

        let count = stream.take(packet_len as u64).read_to_end(&mut raw)?;

        if count == packet_len {
            let padding_len = raw[4] as usize;
            let payload_len = packet_len - padding_len - 1;
            // TODO: Verify packet size (mod 8)
            Ok(Packet::Raw(raw, payload_len))
        }
        else {
            Err(io::Error::new(io::ErrorKind::BrokenPipe, "broken stream"))
        }
    }

    pub fn write_to<W: io::Write>(&self, stream: &mut W) -> Result<()> {
        match self
        {
            &Packet::Raw(ref data, _) => {
                stream.write_all(data)?;
                stream.flush()
            }
            &Packet::Payload(ref payload) => {
                let padding_len = self.padding_len();
                let packet_len = payload.len() + padding_len + 1;

                stream.write_u32::<BigEndian>(packet_len as u32)?;
                stream.write_u8(padding_len as u8)?;
                stream.write_all(&payload)?;
                stream.write_all(&[0u8; 255][..padding_len])?;

                stream.flush()
            }
        }
    }

    pub fn payload(self) -> Vec<u8> {
        match self
        {
            Packet::Raw(data, payload_len) => data[5..payload_len + 5].to_vec(),
            Packet::Payload(payload) => payload,
        }
    }

    pub fn data<'a>(&'a self) -> &'a [u8] {
        match self
        {
            &Packet::Raw(ref data, _) => &data,
            &Packet::Payload(ref payload) => &payload,
        }
    }

    pub fn to_raw(self) -> Result<Packet> {
        match self
        {
            Packet::Raw(_, _) => Ok(self),
            Packet::Payload(ref payload) => {
                let mut buf = Vec::with_capacity(payload.len());
                self.write_to(&mut buf)?;
                Ok(Packet::Raw(buf, payload.len()))
            }
        }
    }

    pub fn reader<'a>(&'a self) -> BufReader<&'a [u8]> {
        match self
        {
            &Packet::Raw(ref data, payload_len) => {
                BufReader::new(&data.as_slice()[6..payload_len + 5])
            }
            &Packet::Payload(ref payload) => {
                BufReader::new(&payload.as_slice()[1..])
            }
        }
    }

    pub fn payload_len(&self) -> usize {
        match self
        {
            &Packet::Raw(_, payload_len) => payload_len,
            &Packet::Payload(ref payload) => payload.len(),
        }
    }

    pub fn padding_len(&self) -> usize {
        let align = 32;

        // Calculate the padding to reach a multiple of 8 bytes
        let padding_len = align - ((self.payload_len() + 5) % align);

        // The padding has to be at least 4 bytes long
        if padding_len < 4 {
            padding_len + align
        }
        else {
            padding_len
        }
    }
}

impl Write for Packet {
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        match self
        {
            &mut Packet::Payload(ref mut payload) => payload.write(buf),
            &mut Packet::Raw(ref mut data, ref mut payload_len) => {
                let count = data.write(buf)?;
                *payload_len += count;
                Ok(count)
            }
        }
    }

    fn flush(&mut self) -> Result<()> {
        Ok(())
    }
}

pub trait ReadPacketExt: ReadBytesExt {
    fn read_string(&mut self) -> Result<Vec<u8>> {
        let len = self.read_u32::<BigEndian>()?;
        self.read_bytes(len as usize)
    }

    fn read_mpint(&mut self) -> Result<BigInt> {
        let len = self.read_u32::<BigEndian>()?;
        let bytes = self.read_bytes(len as usize)?;
        Ok(BigInt::from_signed_bytes_be(bytes.as_slice()))
    }

    fn read_uint32(&mut self) -> Result<u32> {
        Ok(self.read_u32::<BigEndian>()?)
    }

    fn read_bytes(&mut self, len: usize) -> Result<Vec<u8>> {
        let mut buffer = Vec::with_capacity(len);
        self.take(len as u64).read_to_end(&mut buffer)?;
        Ok(buffer)
    }

    fn read_utf8(&mut self) -> Result<String> {
        str::from_utf8(self.read_string()?.as_slice())
            .map(|s| s.to_owned())
            .map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "invalid utf-8")
            })
    }

    fn read_bool(&mut self) -> Result<bool> {
        self.read_u8().map(|i| i != 0)
    }

    fn read_enum_list<T: FromStr>(&mut self) -> Result<Vec<T>> {
        let string = self.read_utf8()?;
        Ok(
            string
                .split(",")
                .filter_map(|l| T::from_str(&l).ok())
                .collect(),
        )
    }

    fn read_name_list(&mut self) -> Result<Vec<String>> {
        let string = self.read_utf8()?;
        Ok(string.split(",").map(|l| l.to_owned()).collect())
    }
}

impl<R: ReadBytesExt> ReadPacketExt for R {}

pub trait WritePacketExt: WriteBytesExt {
    fn write_msg_type(&mut self, msg_type: MessageType) -> Result<()> {
        self.write_u8(msg_type.into())
    }

    fn write_string(&mut self, s: &str) -> Result<()> {
        let bytes = s.as_bytes();
        self.write_bytes(bytes)
    }

    fn write_bytes(&mut self, bytes: &[u8]) -> Result<()> {
        self.write_uint32(bytes.len() as u32)?;
        self.write_all(bytes)
    }

    fn write_raw_bytes(&mut self, bytes: &[u8]) -> Result<()> {
        self.write_all(bytes)
    }

    fn write_bool(&mut self, value: bool) -> Result<()> {
        self.write_u8(if value { 1 } else { 0 })
    }

    fn write_mpint(&mut self, value: BigInt) -> Result<()> {
        let bytes = value.to_signed_bytes_be();
        self.write_bytes(bytes.as_slice())
    }

    fn write_uint32(&mut self, value: u32) -> Result<()> {
        self.write_u32::<BigEndian>(value as u32)
    }

    fn write_list<T: ToString>(&mut self, list: &[T]) -> Result<()> {
        let mut string = String::new();
        let mut iter = list.iter();

        while let Some(item) = iter.next() {
            if !string.is_empty() {
                string += ",";
            }
            string += &*item.to_string();
        }
        self.write_string(&*string)
    }
}

impl<R: WriteBytesExt + ?Sized> WritePacketExt for R {}

impl fmt::Debug for Packet {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Packet({:?}, {} bytes)",
            self.msg_type(),
            self.payload_len()
        )
    }
}
