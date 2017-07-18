use crypto::hmac::Hmac as rcHmac;
use crypto::mac::Mac;
use crypto::sha2::Sha256;
use mac::MacAlgorithm;

pub struct Hmac {
    hmac: Box<rcHmac<Sha256>>,
}

impl Hmac {
    pub fn new(key: &[u8]) -> Hmac {
        let digest = Sha256::new();
        Hmac { hmac: Box::new(rcHmac::new(digest, key)) }
    }
}

impl MacAlgorithm for Hmac {
    fn size(&self) -> usize {
        32
    }

    fn sign(&mut self, data: &[u8], seq: u32, buf: &mut [u8]) {
        let sequence = &[
            ((seq & 0xff000000) >> 24) as u8,
            ((seq & 0x00ff0000) >> 16) as u8,
            ((seq & 0x0000ff00) >> 8) as u8,
            ((seq & 0x000000ff)) as u8,
        ];

        self.hmac.input(sequence);
        self.hmac.input(data);
        self.hmac.raw_result(buf);
        self.hmac.reset();
    }
}
