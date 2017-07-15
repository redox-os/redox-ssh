use public_key::{KeyPair, CryptoSystem};
use std::io::{self, Read, Write};
use std::io::ErrorKind::InvalidData;
use rand::{self, Rng};
use crypto::ed25519;

pub static ED25519: CryptoSystem = CryptoSystem {
    id: "ed25519",
    generate_key_pair: Ed25519KeyPair::generate,
    import: Ed25519KeyPair::import,
    read_public: Ed25519KeyPair::read_public,
};

struct Ed25519KeyPair {
    private: Option<[u8; 64]>,
    public: [u8; 32],
}

impl Ed25519KeyPair {
    fn generate(_: Option<u32>) -> Box<KeyPair> {
        let mut seed = [0u8; 32];
        let mut rng = rand::thread_rng();
        rng.fill_bytes(&mut seed);

        let (private, public) = ed25519::keypair(&seed);
        Box::new(Ed25519KeyPair {
            private: Some(private),
            public: public,
        })
    }

    fn import(mut r: &mut Read) -> io::Result<Box<KeyPair>> {
        use packet::ReadPacketExt;

        if r.read_utf8()? != "ssh-ed25519" {
            return Err(io::Error::new(InvalidData, "not a ED25519 key"));
        }

        if r.read_uint32()? != 32 {
            return Err(io::Error::new(InvalidData, "invalid ED25519 key"));
        }

        let mut public = [0u8; 32];
        r.read_exact(&mut public)?;

        if r.read_uint32()? != 64 {
            return Err(io::Error::new(InvalidData, "invalid ED25519 key"));
        }

        let mut private = [0u8; 64];
        r.read_exact(&mut private)?;

        Ok(Box::new(Ed25519KeyPair {
            public: public,
            private: Some(private),
        }))
    }

    fn read_public(mut r: &mut Read) -> io::Result<Box<KeyPair>> {
        use packet::ReadPacketExt;

        if r.read_uint32()? != 32 {
            return Err(io::Error::new(InvalidData, "invalid ED25519 key"));
        }

        let mut public = [0u8; 32];
        r.read_exact(&mut public)?;

        Ok(Box::new(Ed25519KeyPair {
            private: None,
            public: public,
        }))
    }
}

impl KeyPair for Ed25519KeyPair {
    fn system(&self) -> &'static CryptoSystem {
        &ED25519
    }

    fn has_private(&self) -> bool {
        self.private.is_some()
    }

    fn verify(&self, data: &[u8], signature: &[u8]) -> Result<bool, ()> {
        Ok(ed25519::verify(data, &self.public, signature))
    }

    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, ()> {
        if let Some(private_key) = self.private {
            let signature = ed25519::signature(data, &private_key);
            Ok(signature.to_vec())
        } else {
            Err(())
        }
    }

    fn write_public(&self, w: &mut Write) -> io::Result<()> {
        use packet::WritePacketExt;
        w.write_string("ssh-ed25519")?;
        w.write_bytes(&self.public)
    }

    fn export(&self, w: &mut Write) -> io::Result<()> {
        use packet::WritePacketExt;
        w.write_string("ssh-ed25519")?;
        w.write_bytes(&self.public)?;
        if let Some(private_key) = self.private {
            w.write_bytes(&private_key)?;
        }
        Ok(())
    }
}
