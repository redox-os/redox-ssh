use std::fmt;
use std::str::FromStr;

use error::{ConnectionError, ConnectionResult};

/// Slice of implemented key exchange algorithms, ordered by preference
pub static KEY_EXCHANGE: &[KeyExchangeAlgorithm] =
    &[
    KeyExchangeAlgorithm::CURVE25519_SHA256,
//  KeyExchangeAlgorithm::DH_GROUP_EXCHANGE_SHA1,
];

/// Slice of implemented host key algorithms, ordered by preference
pub static HOST_KEY: &[PublicKeyAlgorithm] = &[
    PublicKeyAlgorithm::SSH_ED25519,
//  PublicKeyAlgorithm::SSH_RSA,
];

/// Slice of implemented encryption algorithms, ordered by preference
pub static ENCRYPTION: &[EncryptionAlgorithm] =
    &[EncryptionAlgorithm::AES256_CTR];

/// Slice of implemented MAC algorithms, ordered by preference
pub static MAC: &[MacAlgorithm] = &[MacAlgorithm::HMAC_SHA2_256];

/// Slice of implemented compression algorithms, ordered by preference
pub static COMPRESSION: &[CompressionAlgorithm] =
    &[CompressionAlgorithm::None, CompressionAlgorithm::Zlib];

/// Find the best matching algorithm
pub fn negotiate<A: PartialEq + Copy>(server: &[A], client: &[A])
    -> ConnectionResult<A> {
    for algorithm in client.iter() {
        if server.iter().any(|a| a == algorithm) {
            return Ok(*algorithm);
        }
    }
    Err(ConnectionError::NegotiationError)
}

#[derive(Clone, Copy, PartialEq, Debug)]
#[repr(C)]
#[allow(non_camel_case_types)]
pub enum KeyExchangeAlgorithm {
    CURVE25519_SHA256,
    ECDH_SHA2_NISTP256,
    ECDH_SHA2_NISTP384,
    ECDH_SHA2_NISTP521,
    DH_GROUP_EXCHANGE_SHA256,
    DH_GROUP_EXCHANGE_SHA1,
    DH_GROUP16_SHA512,
    DH_GROUP18_SHA512,
    DH_GROUP14_SHA256,
    DH_GROUP14_SHA1,
    EXT_INFO_C,
}

impl FromStr for KeyExchangeAlgorithm {
    type Err = ();
    fn from_str(s: &str) -> Result<KeyExchangeAlgorithm, ()> {
        use self::KeyExchangeAlgorithm::*;
        match s
        {
            "curve25519-sha256" => Ok(CURVE25519_SHA256),
            "ecdh-sha2-nistp256" => Ok(ECDH_SHA2_NISTP256),
            "ecdh-sha2-nistp384" => Ok(ECDH_SHA2_NISTP384),
            "ecdh-sha2-nistp521" => Ok(ECDH_SHA2_NISTP521),
            "diffie-hellman-group-exchange-sha256" => Ok(
                DH_GROUP_EXCHANGE_SHA256,
            ),
            "diffie-hellman-group-exchange-sha1" => Ok(DH_GROUP_EXCHANGE_SHA1),
            "diffie-hellman-group16-sha512" => Ok(DH_GROUP16_SHA512),
            "diffie-hellman-group18-sha512" => Ok(DH_GROUP18_SHA512),
            "diffie-hellman-group14-sha256" => Ok(DH_GROUP14_SHA256),
            "diffie-hellman-group14-sha1" => Ok(DH_GROUP14_SHA1),
            "ext-info-c" => Ok(EXT_INFO_C),
            _ => {
                debug!("Unknown kex algorithm: {}", s);
                Err(())
            }
        }
    }
}

impl fmt::Display for KeyExchangeAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::KeyExchangeAlgorithm::*;
        f.write_str(match self
        {
            &CURVE25519_SHA256 => "curve25519-sha256",
            &ECDH_SHA2_NISTP256 => "ecdh-sha2-nistp256",
            &ECDH_SHA2_NISTP384 => "ecdh-sha2-nistp384",
            &ECDH_SHA2_NISTP521 => "ecdh-sha2-nistp521",
            &DH_GROUP_EXCHANGE_SHA256 => "diffie-hellman-group-exchange-sha256",
            &DH_GROUP_EXCHANGE_SHA1 => "diffie-hellman-group-exchange-sha1",
            &DH_GROUP16_SHA512 => "diffie-hellman-group16-sha512",
            &DH_GROUP18_SHA512 => "diffie-hellman-group18-sha512",
            &DH_GROUP14_SHA256 => "diffie-hellman-group14-sha256",
            &DH_GROUP14_SHA1 => "diffie-hellman-group14-sha1",
            &EXT_INFO_C => "ext-info-c",
        })
    }
}

#[derive(Clone, Copy, PartialEq, Debug)]
#[allow(non_camel_case_types)]
pub enum PublicKeyAlgorithm {
    SSH_RSA,
    RSA_SHA2_256,
    RSA_SHA2_512,
    ECDSA_SHA2_NISTP256,
    ECDSA_SHA2_NISTP384,
    ECDSA_SHA2_NISTP521,
    SSH_ED25519,
}

impl FromStr for PublicKeyAlgorithm {
    type Err = ();
    fn from_str(s: &str) -> Result<PublicKeyAlgorithm, ()> {
        use self::PublicKeyAlgorithm::*;
        match s
        {
            "ssh-rsa" => Ok(SSH_RSA),
            "rsa-sha2-256" => Ok(RSA_SHA2_256),
            "rsa-sha2-512" => Ok(RSA_SHA2_512),
            "ecdsa-sha2-nistp256" => Ok(ECDSA_SHA2_NISTP256),
            "ecdsa-sha2-nistp384" => Ok(ECDSA_SHA2_NISTP384),
            "ecdsa-sha2-nistp521" => Ok(ECDSA_SHA2_NISTP521),
            "ssh-ed25519" => Ok(SSH_ED25519),
            _ => {
                debug!("Unknown host key algorithm: {}", s);
                Err(())
            }
        }
    }
}

impl fmt::Display for PublicKeyAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::PublicKeyAlgorithm::*;
        f.write_str(match self
        {
            &SSH_RSA => "ssh-rsa",
            &RSA_SHA2_256 => "rsa-sha2-256",
            &RSA_SHA2_512 => "rsa-sha2-512",
            &ECDSA_SHA2_NISTP256 => "ecdsa-sha2-nistp256",
            &ECDSA_SHA2_NISTP384 => "ecdsa-sha2-nistp384",
            &ECDSA_SHA2_NISTP521 => "ecdsa-sha2-nistp521",
            &SSH_ED25519 => "ssh-ed25519",
        })
    }
}

#[derive(Clone, Copy, PartialEq, Debug)]
#[allow(non_camel_case_types)]
pub enum EncryptionAlgorithm {
    AES128_CTR,
    AES128_CBC,
    AES192_CTR,
    AES192_CBC,
    AES256_CTR,
    AES256_CBC,
    None,
}

impl FromStr for EncryptionAlgorithm {
    type Err = ();
    fn from_str(s: &str) -> Result<EncryptionAlgorithm, ()> {
        use self::EncryptionAlgorithm::*;
        match s
        {
            "aes128-ctr" => Ok(AES128_CTR),
            "aes128-cbc" => Ok(AES128_CBC),
            "aes192-ctr" => Ok(AES192_CTR),
            "aes192-cbc" => Ok(AES192_CBC),
            "aes256-ctr" => Ok(AES256_CTR),
            "aes256-cbc" => Ok(AES256_CBC),
            "none" => Ok(EncryptionAlgorithm::None),
            _ => {
                debug!("Unknown encryption algorithm: `{}`", s);
                Err(())
            }
        }
    }
}

impl fmt::Display for EncryptionAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::EncryptionAlgorithm::*;
        f.write_str(match self
        {
            &AES128_CTR => "aes128-ctr",
            &AES128_CBC => "aes128-cbc",
            &AES192_CTR => "aes192-ctr",
            &AES192_CBC => "aes192-cbc",
            &AES256_CTR => "aes256-ctr",
            &AES256_CBC => "aes256-cbc",
            &EncryptionAlgorithm::None => "none",
        })
    }
}

#[derive(Clone, Copy, PartialEq, Debug)]
#[allow(non_camel_case_types)]
pub enum MacAlgorithm {
    HMAC_SHA1,
    HMAC_SHA2_256,
    HMAC_SHA2_512,
    None,
}

impl FromStr for MacAlgorithm {
    type Err = ();
    fn from_str(s: &str) -> Result<MacAlgorithm, ()> {
        use self::MacAlgorithm::*;
        match s
        {
            "hmac-sha1" => Ok(MacAlgorithm::HMAC_SHA1),
            "hmac-sha2-256" => Ok(MacAlgorithm::HMAC_SHA2_256),
            "hmac-sha2-512" => Ok(MacAlgorithm::HMAC_SHA2_512),
            _ => {
                debug!("Unknown mac algorithm: {}", s);
                Err(())
            }
        }
    }
}

impl fmt::Display for MacAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::MacAlgorithm::*;
        f.write_str(match self
        {
            &HMAC_SHA1 => "hmac-sha1",
            &HMAC_SHA2_256 => "hmac-sha2-256",
            &HMAC_SHA2_512 => "hmac-sha2-512",
            &MacAlgorithm::None => "none",
        })
    }
}

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum CompressionAlgorithm {
    Zlib,
    None,
}

impl FromStr for CompressionAlgorithm {
    type Err = ();
    fn from_str(s: &str) -> Result<CompressionAlgorithm, ()> {
        match s
        {
            "zlib" => Ok(CompressionAlgorithm::Zlib),
            "none" => Ok(CompressionAlgorithm::None),
            _ => {
                debug!("Unknown compression algorithm: {}", s);
                Err(())
            }
        }
    }
}

impl fmt::Display for CompressionAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(match self
        {
            &CompressionAlgorithm::Zlib => "zlib",
            &CompressionAlgorithm::None => "none",
        })
    }
}
