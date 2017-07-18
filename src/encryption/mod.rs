use std::io::{self, Read};

mod aes_ctr;

pub use self::aes_ctr::AesCtr;

pub trait Encryption {
    fn encrypt(&mut self, data: &[u8], buf: &mut [u8]);
    fn decrypt(&mut self, data: &[u8], buf: &mut [u8]);
}

pub struct Decryptor<'a> {
    encryption: &'a mut Encryption,
    stream: &'a mut Read,
}

impl<'a> Decryptor<'a> {
    pub fn new(encryption: &'a mut Encryption, stream: &'a mut Read)
        -> Decryptor<'a> {
        Decryptor {
            encryption: encryption,
            stream: stream,
        }
    }
}

impl<'a> Read for Decryptor<'a> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut tmp = vec![0; buf.len()];
        let count = self.stream.read(tmp.as_mut_slice())?;
        self.encryption.decrypt(
            &tmp.as_slice()[0..count],
            &mut buf[0..count],
        );
        Ok(count)
    }
}
