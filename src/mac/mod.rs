mod hmac;

pub use self::hmac::Hmac;

pub trait MacAlgorithm {
    fn size(&self) -> usize;
    fn sign(&mut self, data: &[u8], seq: u32, buf: &mut [u8]);
}
