use std::io::ErrorKind::InvalidData;
use std::io::{self, Read, Write};

use ed25519_dalek::ed25519::signature::SignerMut;
use ed25519_dalek::{SecretKey, Signature, SigningKey, VerifyingKey};
use rand::rngs::OsRng;
// use crypto::ed25519;

use crate::public_key::{
    CryptoSystem, KeyPair, KeyPairIdValidationError, SigningError,
};

pub static ED25519: CryptoSystem = CryptoSystem {
    id: "ed25519",
    generate_key_pair: Ed25519KeyPair::generate,
    import: Ed25519KeyPair::import,
    read_public: Ed25519KeyPair::read_public,
};

struct Ed25519KeyPair {
    // This should be 32 bytes as mandated for [ed25519](https://www.rfc-editor.org/rfc/rfc8032#section-5.1.5)
    private: Option<SigningKey>, //[u8; 64]>,
    public: VerifyingKey,        // [u8; 32],
}

impl Ed25519KeyPair {
    fn generate(_: Option<u32>) -> Box<dyn KeyPair> {
        let mut csprng = OsRng;
        let private: SigningKey = SigningKey::generate(&mut csprng);
        let public: VerifyingKey = private.verifying_key();

        Box::new(Ed25519KeyPair {
            private: Some(private),
            public,
        })
    }

    fn import(mut r: &mut dyn Read) -> io::Result<Box<dyn KeyPair>> {
        use crate::packet::ReadPacketExt;

        if r.read_utf8()? != "ssh-ed25519" {
            return Err(io::Error::new(
                InvalidData,
                "Not a ED25519 key (in custom format), invalid header",
            ));
        }

        if r.read_uint32()? != 32 {
            return Err(io::Error::new(InvalidData, "Invalid ED25519 key (in custom format), verifying key length is invalid"));
        }

        let mut public = [0u8; 32];
        r.read_exact(&mut public)?;
        let public = VerifyingKey::from_bytes(&public)
            .expect("Failed to construct verifying keys from the bytes read"); // TODO

        if r.read_uint32()? != 32 {
            return Err(io::Error::new(InvalidData, "Invalid ED25519 key (in custom format), secret key length is invalid"));
        }

        let mut private: SecretKey = [0u8; 32];
        r.read_exact(&mut private)?;
        let private = SigningKey::from_bytes(&private);

        Ok(Box::new(Ed25519KeyPair {
            public,
            private: Some(private),
        }))
    }

    fn read_public(mut r: &mut dyn Read) -> io::Result<Box<dyn KeyPair>> {
        use crate::packet::ReadPacketExt;

        if r.read_uint32()? != 32 {
            return Err(io::Error::new(InvalidData, "invalid ED25519 key"));
        }

        let mut public = [0u8; 32];
        r.read_exact(&mut public)?;
        let public = VerifyingKey::from_bytes(&public).unwrap(); // TODO

        Ok(Box::new(Ed25519KeyPair {
            private: None,
            public,
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

    fn verify(
        &self,
        data: &[u8],
        signature: &[u8],
    ) -> Result<bool, KeyPairIdValidationError> {
        use crate::packet::ReadPacketExt;
        use std::io::Cursor;

        const EXPECTED_ID: &[u8] = b"ssh-ed25519";

        let mut reader = Cursor::new(signature);
        let received_id = reader.read_string().unwrap_or_default();

        if received_id == EXPECTED_ID {
            if let Ok(sig) = reader.read_string() {
                // TODO: .read_string() {
                let sig_array: &[u8; 64] = sig
                    .as_slice()
                    .try_into()
                    .expect("slice with incorrect length"); // TODO
                let sig = Signature::from_bytes(sig_array); // TODO
                let res = self.public.verify_strict(data, &sig);
                return Ok(res.is_ok());
                // return Ok(ed25519::verify(data, &self.public,
                // sig.as_slice()));
            }
        }
        Err(KeyPairIdValidationError {
            received_id,
            expected_id: EXPECTED_ID,
        })
    }

    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, SigningError> {
        use crate::packet::WritePacketExt;
        if let Some(mut private_key) = self.private.clone() {
            let mut result = Vec::new();
            let sig = private_key.sign(data);
            // let sig = ed25519::signature(data, &private_key);
            result.write_string("ssh-ed25519")?;
            result.write_bytes(&sig.to_bytes())?;
            Ok(result)
        }
        else {
            Err(SigningError::NoPrivateKey)
        }
    }

    fn write_public(&self, w: &mut dyn Write) -> io::Result<()> {
        use crate::packet::WritePacketExt;
        w.write_string("ssh-ed25519")?;
        w.write_bytes(self.public.as_bytes())
    }

    fn export(&self, w: &mut dyn Write) -> io::Result<()> {
        use crate::packet::WritePacketExt;
        w.write_string("ssh-ed25519")?;
        w.write_bytes(self.public.as_bytes())?;
        if let Some(private_key) = &self.private {
            w.write_bytes(private_key.as_bytes())?;
        }
        Ok(())
    }
}
