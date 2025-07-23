use super::TlsConfig;
use anyhow::Result;
use serde::Deserialize;
use std::collections::HashMap;

#[derive(Debug, Deserialize, Clone)]
pub struct Container {
    #[serde(rename = "Names")]
    _names: Vec<String>,
    #[serde(rename = "Labels")]
    pub labels: HashMap<String, String>,
    #[serde(rename = "State")]
    state: String,
}

#[derive(Debug, Clone)]
pub struct WorkerContainer {
    pub container: Container,
    pub worker_node: String,
}

impl WorkerContainer {
    pub fn proxy_domain(&self) -> Option<&str> {
        self.container
            .labels
            .get("proxy.domain")
            .map(|s| s.as_str())
    }

    pub fn proxy_port(&self) -> Option<u16> {
        self.container
            .labels
            .get("proxy.port")
            .and_then(|p| p.parse().ok())
    }

    pub fn is_proxy_eligible(&self) -> bool {
        self.container.state == "running"
            && self.proxy_domain().is_some()
            && self.proxy_port().is_some()
    }

    pub fn upstream_dial(&self) -> Result<String> {
        let host = extract_host_from_url(&self.worker_node)?;
        let port = self
            .proxy_port()
            .ok_or_else(|| anyhow::anyhow!("No proxy.port"))?;
        Ok(format!("{}:{}", host, port))
    }

    pub fn tls_config(&self) -> TlsConfig {
        let cert = self.container.labels.get("tls.cert").cloned();
        let key = self.container.labels.get("tls.key").cloned();
        let acme_ca = self.container.labels.get("tls.acme_ca").cloned();
        TlsConfig { cert, key, acme_ca }
    }
}

fn extract_host_from_url(url: &str) -> Result<String> {
    let parsed = url::Url::parse(url)?;
    Ok(parsed
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("No host in URL"))?
        .to_string())
}
