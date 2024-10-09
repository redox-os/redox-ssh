use std::io::{self, Read};

// mod aes_ctr;
mod aes_ctr_new;

// pub use self::aes_ctr::AesCtr;
pub use self::aes_ctr_new::AesCtr;

pub trait Encryption {
    fn encrypt(&mut self, data: &[u8], buf: &mut [u8]);
    fn decrypt(&mut self, data: &[u8], buf: &mut [u8]);
}

pub struct Decryptor<'a> {
    encryption: &'a mut dyn Encryption,
    stream: &'a mut dyn Read,
}

impl<'a> Decryptor<'a> {
    pub fn new(
        encryption: &'a mut dyn Encryption,
        stream: &'a mut dyn Read,
    ) -> Decryptor<'a> {
        Decryptor { encryption, stream }
    }
}

impl Read for Decryptor<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut tmp = vec![0; buf.len()];
        let count = self.stream.read(tmp.as_mut_slice())?;
        self.encryption
            .decrypt(&tmp.as_slice()[0..count], &mut buf[0..count]);
        Ok(count)
    }
}
