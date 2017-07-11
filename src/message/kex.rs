use std::str::FromStr;

#[derive(Debug)]
pub struct KeyExchangeInit {
    pub cookie: Vec<u8>,
    pub kex_algorithms: Vec<KeyExchangeAlgorithm>,
    pub server_host_key_algorithms: Vec<HostKeyAlgorithm>,
    pub encryption_algorithms_client_to_server: Vec<EncryptionAlgorithm>,
    pub encryption_algorithms_server_to_client: Vec<EncryptionAlgorithm>,
    pub mac_algorithms_client_to_server: Vec<MacAlgorithm>,
    pub mac_algorithms_server_to_client: Vec<MacAlgorithm>,
    pub compression_algorithms_client_to_server: Vec<CompressionAlgorithm>,
    pub compression_algorithms_server_to_client: Vec<CompressionAlgorithm>,
    pub languages_client_to_server: Vec<Language>,
    pub languages_server_to_client: Vec<Language>,
    pub first_kex_packet_follows: bool
}

#[derive(Debug)]
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
    EXT_INFO_C
}

impl FromStr for KeyExchangeAlgorithm {
    type Err = ();
    fn from_str(s: &str) -> Result<KeyExchangeAlgorithm, ()> {
        match s {
            "curve25519-sha256" =>
                Ok(KeyExchangeAlgorithm::CURVE25519_SHA256),
            "ecdh-sha2-nistp256" =>
                Ok(KeyExchangeAlgorithm::ECDH_SHA2_NISTP256),
            "ecdh-sha2-nistp384" =>
                Ok(KeyExchangeAlgorithm::ECDH_SHA2_NISTP384),
            "ecdh-sha2-nistp521" =>
                Ok(KeyExchangeAlgorithm::ECDH_SHA2_NISTP521),
            "diffie-hellman-group16-sha512" =>
                Ok(KeyExchangeAlgorithm::DH_GROUP16_SHA512),
            "diffie-hellman-group18-sha512" =>
                Ok(KeyExchangeAlgorithm::DH_GROUP18_SHA512),
            "diffie-hellman-group14-sha256" =>
                Ok(KeyExchangeAlgorithm::DH_GROUP14_SHA256),
            "diffie-hellman-group14-sha1" =>
                Ok(KeyExchangeAlgorithm::DH_GROUP14_SHA1),
            "diffie-hellman-group-exchange-sha256" =>
                Ok(KeyExchangeAlgorithm::DH_GROUP_EXCHANGE_SHA256),
            "diffie-hellman-group-exchange-sha1" =>
                Ok(KeyExchangeAlgorithm::DH_GROUP_EXCHANGE_SHA1),
            "ext-info-c" =>
                Ok(KeyExchangeAlgorithm::EXT_INFO_C),
            _ => { println!("Unknown kex algorithm: {}", s); Err(()) }
        }
    }
}


#[derive(Debug)]
#[allow(non_camel_case_types)]
pub enum HostKeyAlgorithm {
    SSH_RSA,
    RSA_SHA2_256,
    RSA_SHA2_512,
    ECDSA_SHA2_NISTP256,
    ECDSA_SHA2_NISTP384,
    ECDSA_SHA2_NISTP521,
    SSH_ED25519
}

impl FromStr for HostKeyAlgorithm {
    type Err = ();
    fn from_str(s: &str) -> Result<HostKeyAlgorithm, ()> {
        match s {
            "ssh-rsa" => Ok(HostKeyAlgorithm::SSH_RSA),
            "rsa-sha2-256" => Ok(HostKeyAlgorithm::RSA_SHA2_256),
            "rsa-sha2-512" => Ok(HostKeyAlgorithm::RSA_SHA2_512),
            "ecdsa-sha2-nistp256" => Ok(HostKeyAlgorithm::ECDSA_SHA2_NISTP256),
            "ecdsa-sha2-nistp384" => Ok(HostKeyAlgorithm::ECDSA_SHA2_NISTP384),
            "ecdsa-sha2-nistp521" => Ok(HostKeyAlgorithm::ECDSA_SHA2_NISTP521),
            "ssh-ed25519" => Ok(HostKeyAlgorithm::SSH_ED25519),
            _ => { println!("Unknown host key algorithm: {}", s); Err(()) }
        }
    }
}

#[derive(Debug)]
#[allow(non_camel_case_types)]
pub enum EncryptionAlgorithm {
    AES128_CTR,
    AES128_CBC,
    AES192_CTR,
    AES192_CBC,
    AES256_CTR,
    AES256_CBC,
    None
}

impl FromStr for EncryptionAlgorithm {
    type Err = ();
    fn from_str(s: &str) -> Result<EncryptionAlgorithm, ()> {
        match s {
            "aes128-ctr" => Ok(EncryptionAlgorithm::AES128_CTR),
            "aes128-cbc" => Ok(EncryptionAlgorithm::AES128_CBC),
            "aes192-ctr" => Ok(EncryptionAlgorithm::AES192_CTR),
            "aes192-cbc" => Ok(EncryptionAlgorithm::AES192_CBC),
            "aes256-ctr" => Ok(EncryptionAlgorithm::AES256_CTR),
            "aes256-cbc" => Ok(EncryptionAlgorithm::AES256_CBC),
            "none" => Ok(EncryptionAlgorithm::None),
            _ => { println!("Unknown encryption algorithm: `{}`", s); Err(()) }
        }
    }
}

#[derive(Debug)]
#[allow(non_camel_case_types)]
pub enum MacAlgorithm {
    HMAC_SHA1,
    HMAC_SHA2_256,
    HMAC_SHA2_512,
    None
}

impl FromStr for MacAlgorithm {
    type Err = ();
    fn from_str(s: &str) -> Result<MacAlgorithm, ()> {
        match s {
            "hmac-sha1" => Ok(MacAlgorithm::HMAC_SHA1),
            "hmac-sha2-256" => Ok(MacAlgorithm::HMAC_SHA2_256),
            "hmac-sha2-512" => Ok(MacAlgorithm::HMAC_SHA2_512),
            _ => { println!("Unknown mac algorithm: {}", s); Err(()) }
        }
    }
}

#[derive(Debug)]
pub enum CompressionAlgorithm {
    Zlib,
    None
}

impl FromStr for CompressionAlgorithm {
    type Err = ();
    fn from_str(s: &str) -> Result<CompressionAlgorithm, ()> {
        match s {
            "zlib" => Ok(CompressionAlgorithm::Zlib),
            "none" => Ok(CompressionAlgorithm::None),
            _ => { println!("Unknown compression algorithm: {}", s); Err(()) }
        }
    }
}

#[derive(Debug)]
pub struct Language(pub String);

