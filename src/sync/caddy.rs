use super::{SyncService, TlsConfig};

use sha2::{Digest, Sha256};
use serde::Serialize;
use std::collections::HashMap;

#[derive(Debug, PartialEq, Clone)]
pub struct DomainGroup {
    pub domain: String,
    pub upstreams: Vec<String>,
    pub headers: HeaderConfig,
    pub tls: TlsConfig,
}

#[derive(Serialize)]
struct CaddyAcmeIssuer {
    module: String,
    ca: String,
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
struct CaddyTlsPolicy {
    #[serde(skip_serializing_if = "Option::is_none")]
    certificate: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    issuer: Option<CaddyAcmeIssuer>,
}

#[derive(Serialize)]
pub struct CaddyUpstream {
    dial: String,
}


#[derive(Serialize)]
pub struct CaddyHandler {
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


#[derive(Default, Debug, PartialEq, Clone)]
pub struct HeaderConfig {
    set: HashMap<String, Vec<String>>,
    add: HashMap<String, Vec<String>>,
    delete: Vec<String>,
}

impl HeaderConfig {
    pub fn from_labels(labels: &HashMap<String, String>) -> Self {
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

impl SyncService {
        pub async fn create_caddy_route(&self, group: &DomainGroup) -> Result<(), anyhow::Error > {
        let mut handlers = Vec::new();

        if group.headers.has_rules() {
            handlers.push(group.headers.to_caddy_handler());
        }

        let upstreams: Vec<_> = group
            .upstreams
            .iter()
            .map(|dial| CaddyUpstream { dial: dial.clone() })
            .collect();

        handlers.push(CaddyHandler {
            handler: "reverse_proxy".to_string(),
            upstreams: Some(upstreams),
            set: None,
            add: None,
            delete: None,
            lb_policy: Some(self.config.lb_policy.clone()),
        });

        let route = CaddyRoute {
            id: generate_route_id(&group.domain),
            r#match: vec![CaddyMatcher {
                host: vec![group.domain.clone()],
            }],
            handle: handlers,
            terminal: Some(true),
        };

        if group.tls.is_manual() || group.tls.is_acme() {
            self.setup_tls(&group.domain, &group.tls).await?;
        }

        let url = format!(
            "{}/config/apps/http/servers/srv0/routes",
            self.config.caddy_admin
        );
        let response = self.client.patch(&url).json(&route).send().await?;

        if !response.status().is_success() {
            let error = response.text().await.unwrap_or_default();
            return Err(anyhow::anyhow!("Route creation failed: {}", error));
        }

        Ok(())
    }

    pub async fn remove_caddy_route(&self, domain: &str) -> Result<(), anyhow::Error> {
        let route_id = generate_route_id(domain);
        let url = format!(
            "{}/config/apps/http/servers/srv0/routes/{}",
            self.config.caddy_admin, route_id
        );

        let response = self.client.delete(&url).send().await?;
        if !response.status().is_success() && response.status().as_u16() != 404 {
            let error = response.text().await.unwrap_or_default();
            return Err(anyhow::anyhow!("Route removal failed: {}", error));
        }
        Ok(())
    }

    async fn setup_tls(&self, domain: &str, tls: &TlsConfig) -> Result<(), anyhow::Error> {
        let policy = if tls.is_manual() {
            CaddyTlsPolicy {
                certificate: tls.cert.clone(),
                key: tls.key.clone(),
                issuer: None,
            }
        } else if tls.is_acme() {
            CaddyTlsPolicy {
                certificate: None,
                key: None,
                issuer: Some(CaddyAcmeIssuer {
                    module: "acme".to_string(),
                    ca: tls.acme_ca.clone().unwrap(),
                }),
            }
        } else {
            return Ok(());
        };

        let url = format!("{}/config/apps/tls/certificates", self.config.caddy_admin);
        let response = self.client.patch(&url).json(&policy).send().await?;

        if !response.status().is_success() {
            let error = response.text().await.unwrap_or_default();
            return Err(anyhow::anyhow!(
                "TLS setup failed for {}: {}",
                domain,
                error
            ));
        }

        Ok(())
    }
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
