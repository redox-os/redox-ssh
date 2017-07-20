use crypto::aes::{KeySize, ctr};
use crypto::symmetriccipher::SynchronousStreamCipher;

use encryption::Encryption;

pub struct AesCtr {
    cipher: Box<SynchronousStreamCipher + 'static>,
}

impl AesCtr {
    pub fn new(key: &[u8], iv: &[u8]) -> AesCtr {
        AesCtr { cipher: ctr(KeySize::KeySize256, key, &iv[0..16]) }
    }
}

impl Encryption for AesCtr {
    fn encrypt(&mut self, data: &[u8], buf: &mut [u8]) {
        self.cipher.process(data, buf);
    }

    fn decrypt(&mut self, data: &[u8], buf: &mut [u8]) {
        self.cipher.process(data, buf);
    }
}
