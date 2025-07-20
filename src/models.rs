use anyhow::{Context, Result};
use reqwest_eventsource::{Event, EventSource};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap};


// ============================================================================
// Domain Models
// ============================================================================

/// Podman container representation from API
#[derive(Debug, Deserialize, Clone)]
struct Container {
    #[serde(rename = "Names")]
    _names: Vec<String>,
    #[serde(rename = "Labels")]
    labels: HashMap<String, String>,
    #[serde(rename = "State")]
    state: String,
}

/// Container paired with its source worker node
#[derive(Debug, Clone)]
struct WorkerContainer {
    container: Container,
    worker_node: String,
}

impl WorkerContainer {
    /// Extract proxy domain from container labels
    fn proxy_domain(&self) -> Option<&str> {
        self.container.labels.get("proxy.domain").map(|s| s.as_str())
    }

    /// Extract proxy port from container labels
    fn proxy_port(&self) -> Option<u16> {
        self.container
            .labels
            .get("proxy.port")
            .and_then(|port| port.parse().ok())
    }

    /// Check if container is eligible for proxying
    fn is_proxy_eligible(&self) -> bool {
        self.container.state == "running" 
            && self.proxy_domain().is_some() 
            && self.proxy_port().is_some()
    }

    /// Generate upstream dial address for Caddy
    fn upstream_dial(&self) -> Result<String> {
        let host = extract_host_from_url(&self.worker_node)?;
        let port = self.proxy_port()
            .ok_or_else(|| anyhow::anyhow!("No proxy.port label found"))?;
        Ok(format!("{}:{}", host, port))
    }

    /// Generate tls configuration for Caddy
    fn tls_config(&self) -> TlsConfig {
        let cert = self.container.labels.get("tls.cert").cloned();
        let key = self.container.labels.get("tls.key").cloned();
        let acme_ca = self.container.labels.get("tls.acme_ca").cloned();
        TlsConfig { cert, key, acme_ca }
    }
}
