pub enum AuthMethod {
    PublicKey, Password, HostBased, None
}

pub struct AuthRequest {
    user: String,
    service: String,
    method: AuthMethod
}
