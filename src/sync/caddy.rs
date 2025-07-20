
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::HashMap;


#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TlsConfig {
    pub cert: Option<String>,
    pub key: Option<String>,
    pub acme_ca: Option<String>,
}


#[derive(Serialize)]
struct CaddyRoute {
    #[serde(rename = "@id")]
    id: String,
    r#match: Vec<CaddyMatcher>,
    handle: Vec<CaddyHandler>,
    #[serde(skip_serializing_if = "Option::is_none")]
    terminal: Option<bool>,
}

#[derive(Serialize)]
struct CaddyMatcher {
    host: Vec<String>,
}

#[derive(Serialize)]
struct CaddyHandler {
    handler: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    upstreams: Option<Vec<CaddyUpstream>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    set: Option<HashMap<String, Vec<String>>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    add: Option<HashMap<String, Vec<String>>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    delete: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    lb_policy: Option<String>,
}

#[derive(Serialize)]
struct CaddyUpstream {
    dial: String,
}

#[derive(Serialize)]
struct CaddyTlsPolicy {
    #[serde(skip_serializing_if = "Option::is_none")]
    certificate: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    issuer: Option<CaddyAcmeIssuer>,
}

#[derive(Serialize)]
struct CaddyAcmeIssuer {
    module: String,
    ca: String,
}

#[derive(Default, Debug, PartialEq, Clone)]
struct HeaderConfig {
    set: HashMap<String, Vec<String>>,
    add: HashMap<String, Vec<String>>,
    delete: Vec<String>,
}

impl HeaderConfig {
    fn from_labels(labels: &HashMap<String, String>) -> Self {
        let mut config = HeaderConfig::default();
        for (key, value) in labels {
            if let Some(name) = key.strip_prefix("proxy.header.set.") {
                config.set.insert(name.to_string(), vec![value.clone()]);
            } else if let Some(name) = key.strip_prefix("proxy.header.add.") {
                config
                    .add
                    .entry(name.to_string())
                    .or_default()
                    .push(value.clone());
            } else if let Some(name) = key.strip_prefix("proxy.header.delete.") {
                if value == "true" {
                    config.delete.push(name.to_string());
                }
            }
        }
        config
    }

    pub fn has_rules(&self) -> bool {
        !self.set.is_empty() || !self.add.is_empty() || !self.delete.is_empty()
    }

    pub fn to_caddy_handler(&self) -> CaddyHandler {
        CaddyHandler {
            handler: "headers".to_string(),
            upstreams: None,
            set: if self.set.is_empty() {
                None
            } else {
                Some(self.set.clone())
            },
            add: if self.add.is_empty() {
                None
            } else {
                Some(self.add.clone())
            },
            delete: if self.delete.is_empty() {
                None
            } else {
                Some(self.delete.clone())
            },
            lb_policy: None,
        }
    }
}

#[derive(Debug, PartialEq, Clone)]
pub struct DomainGroup {
    pub domain: String,
    pub upstreams: Vec<String>,
    pub headers: HeaderConfig,
    pub tls: TlsConfig,
}


#[derive(Debug)]
enum ChangeType {
    Add,
    Update,
    Remove,
}

fn generate_route_id(domain: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(domain.as_bytes());
    let hash = hasher.finalize();

    let hash_str = hash[..8]
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<String>();
    format!("route_{}", hash_str)
}


