#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TlsConfig {
    pub cert: Option<String>,
    pub key: Option<String>,
    pub acme_ca: Option<String>,
}

impl TlsConfig {
    pub fn is_manual(&self) -> bool {
        self.cert.is_some() && self.key.is_some()
    }

    pub fn is_acme(&self) -> bool {
        self.acme_ca.is_some()
    }
}
