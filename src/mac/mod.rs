// mod hmac;
mod hmac_new;

// pub use self::hmac::Hmac;
pub use self::hmac_new::ExtHmac as Hmac;

pub trait MacAlgorithm {
    fn size(&self) -> usize;
    fn sign(&mut self, data: &[u8], seq: u32, buf: &mut [u8]);
}
