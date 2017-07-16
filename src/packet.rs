use std::fmt;
use std::io::{self, BufReader, Read, Result, Write};
use std::str::{self, FromStr};
use std::string::ToString;

use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};

use message::MessageType;
use num_bigint::BigInt;

pub struct Packet {
    payload: Vec<u8>,
}

impl Packet {
    pub fn new(msg_type: MessageType) -> Packet {
        Packet { payload: (&[msg_type.into()]).to_vec() }
    }

    pub fn msg_type(&self) -> MessageType {
        self.payload[0].into()
    }

    pub fn read_from<R: io::Read>(stream: &mut R) -> Result<Packet> {
        let mac_len = 0;

        let packet_len = stream.read_u32::<BigEndian>()? as usize;
        let padding_len = stream.read_u8()? as usize;
        let payload_len = packet_len - padding_len - 1;

        // TODO: Prevent packets that are too large

        let mut payload = Vec::with_capacity(payload_len);
        let mut padding = Vec::with_capacity(padding_len);
        // let mut mac = Vec::with_capacity(mac_len);

        stream.take(payload_len as u64).read_to_end(&mut payload)?;
        stream.take(padding_len as u64).read_to_end(&mut padding)?;

        // if mac_len > 0 {
        //     stream.take(mac_len as u64).read_to_end(&mut mac);
        // }

        Ok(Packet { payload: payload })
    }

    pub fn write_to<W: io::Write>(&self, stream: &mut W) -> Result<()> {
        let padding_len = self.padding_len();
        let packet_len = self.payload.len() + padding_len + 1;

        stream.write_u32::<BigEndian>(packet_len as u32)?;
        stream.write_u8(padding_len as u8)?;
        stream.write(&self.payload)?;
        stream.write(&[0u8; 255][..padding_len])?;
        stream.flush()?;

        Ok(())
    }

    pub fn writer<'a>(&'a mut self) -> &'a mut Write {
        &mut self.payload
    }

    pub fn with_writer(
        &mut self,
        f: &Fn(&mut Write) -> Result<()>,
    ) -> Result<()> {
        f(&mut self.payload)
    }

    pub fn reader<'a>(&'a self) -> BufReader<&'a [u8]> {
        BufReader::new(&self.payload.as_slice()[1..])
    }

    pub fn padding_len(&self) -> usize {
        // Calculate the padding to reach a multiple of 8 bytes
        let padding_len = 8 - ((self.payload.len() + 5) % 8);

        // The padding has to be at least 4 bytes long
        if padding_len < 4 {
            padding_len + 8
        }
        else {
            padding_len
        }
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
        Ok(
            str::from_utf8(self.read_string()?.as_slice())
                .unwrap_or("")
                .to_owned(),
        )
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
            self.payload.len()
        )
    }
}
