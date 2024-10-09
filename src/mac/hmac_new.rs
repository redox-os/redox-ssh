use hmac::{Hmac, Mac};
use sha2::Sha256;

use super::MacAlgorithm;

type HmacSha256 = Hmac<Sha256>;

pub struct ExtHmac {
    hmac: HmacSha256,
}

impl ExtHmac {
    pub fn new(key: &[u8]) -> Self {
        Self {
            hmac: HmacSha256::new_from_slice(key).unwrap(),
        }
    }
}

impl MacAlgorithm for ExtHmac {
    fn size(&self) -> usize {
        32
    }

    fn sign(&mut self, data: &[u8], seq: u32, buf: &mut [u8]) {
        let sequence = &[
            ((seq & 0xff000000) >> 24) as u8,
            ((seq & 0x00ff0000) >> 16) as u8,
            ((seq & 0x0000ff00) >> 8) as u8,
            (seq & 0x000000ff) as u8,
        ];
        self.hmac.update(sequence);
        self.hmac.update(data);
        let result = self.hmac.clone().finalize();
        buf.copy_from_slice(&result.into_bytes());
        self.hmac.reset();
    }
}
