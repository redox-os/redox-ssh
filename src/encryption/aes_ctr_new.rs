use aes::cipher::generic_array::GenericArray;
use aes::cipher::{KeyIvInit, StreamCipher};

use super::Encryption;

type ThisCipher = ctr::Ctr128BE<aes::Aes256>;

pub struct AesCtr {
    cipher: ThisCipher,
}

impl AesCtr {
    pub fn new(key: &[u8], iv: &[u8]) -> Self {
        let key: [u8; 32] =
            key.try_into().expect("slice with incorrect length");
        let key = GenericArray::from_slice(&key);
        let iv: [u8; 16] =
            iv[..16].try_into().expect("slice with incorrect length");
        let iv = GenericArray::from_slice(&iv);
        let cipher = ThisCipher::new(key, iv);
        Self { cipher }
    }
}

impl AesCtr {
    fn apply(&mut self, input: &[u8], output: &mut [u8]) {
        self.cipher.apply_keystream_b2b(input, output).unwrap();
    }
}

impl Encryption for AesCtr {
    fn encrypt(&mut self, data: &[u8], buf: &mut [u8]) {
        self.apply(data, buf)
    }

    fn decrypt(&mut self, data: &[u8], buf: &mut [u8]) {
        self.apply(data, buf)
    }
}
