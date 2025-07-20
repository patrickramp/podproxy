use super::*;

use anyhow::{Context, Result};
use futures_util::StreamExt;
use reqwest;
use reqwest_eventsource::{Event, EventSource};
use serde_json::Value;
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
    time::Duration,
};
use tokio::{
    signal,
    sync::{Mutex, mpsc},
    time::sleep,
};
use tracing::{error, info, warn};

impl TlsConfig {
    fn is_manual(&self) -> bool {
        self.cert.is_some() && self.key.is_some()
    }

    fn is_acme(&self) -> bool {
        self.acme_ca.is_some()
    }
}

pub struct SyncService {
    config: Config,
    client: reqwest::Client,
    current_routes: Arc<Mutex<HashMap<String, DomainGroup>>>,
    debounce_tx: mpsc::UnboundedSender<()>,
}

impl SyncService {
    pub fn new(config: Config) -> Result<Arc<Self>> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(config.reconnect_timeout))
            .build()
            .context("Failed to create HTTP client")?;

        let (debounce_tx, debounce_rx) = mpsc::unbounded_channel();
        let current_routes = Arc::new(Mutex::new(HashMap::new()));

        let service = Arc::new(Self {
            config,
            client,
            current_routes,
            debounce_tx,
        });
        let serivce_clone = service.clone();

        tokio::spawn(async move {
            serivce_clone.debounce_handler(debounce_rx).await;
        });

        Ok(service)
    }

    async fn debounce_handler(&self, mut rx: mpsc::UnboundedReceiver<()>) {
        let debounce_duration = Duration::from_millis(self.config.debounce_ms);
        let mut interval = tokio::time::interval(debounce_duration);

        loop {
            tokio::select! {
                _ = interval.tick() => {
                    if rx.try_recv().is_ok() {
                        if let Err(e) = self.sync_containers().await {
                            error!("Debounced sync failed: {}", e);
                        }
                    }
                }
                _ = rx.recv() => {}
            }
        }
    }

    pub async fn run(&self) -> Result<()> {
        self.sync_containers()
            .await
            .context("Initial sync failed")?;
        info!(
            "Service initialized with {} workers",
            self.config.worker_nodes.len()
        );

        tokio::select! {
            result = self.run_event_loop() => {
                error!("Event loop terminated: {:?}", result);
                result
            }
            _ = signal::ctrl_c() => {
                info!("Shutdown signal received");
                Ok(())
            }
        }
    }

    async fn run_event_loop(&self) -> Result<()> {
        let mut retry_count = 0;

        loop {
            let event_futures: Vec<_> = self
                .config
                .worker_nodes
                .iter()
                .map(|node| Box::pin(self.watch_node_events(node.clone())))
                .collect();

            match futures_util::future::select_all(event_futures).await {
                (Ok(_), _, _) => retry_count = 0,
                (Err(e), _, _) => {
                    retry_count += 1;
                    let backoff = std::cmp::min(300, 2_u64.pow(retry_count.min(8)));

                    error!("Event stream failed ({}): {}", retry_count, e);
                    if retry_count > self.config.max_retries {
                        return Err(e).context("Max retries exceeded");
                    }

                    sleep(Duration::from_secs(backoff)).await;
                }
            }
        }
    }

    async fn watch_node_events(&self, worker_node: String) -> Result<()> {
        let events_url = format!("{}/v5.0.0/libpod/events", worker_node);
        let mut event_source = EventSource::get(&events_url);
        info!("Connected to {}", worker_node);

        while let Some(event) = event_source.next().await {
            match event {
                Ok(Event::Message(msg)) => {
                    if let Err(e) = self.handle_event(&msg.data, &worker_node).await {
                        warn!("Event handling failed: {}", e);
                    }
                }
                Err(e) => return Err(e.into()),
                _ => {}
            }
        }
        Ok(())
    }

    async fn handle_event(&self, data: &str, _worker_node: &str) -> Result<()> {
        let event: Value = serde_json::from_str(data)?;

        if let Some(action) = event["Action"].as_str() {
            match action {
                "start" | "stop" | "die" | "remove" => {
                    let _ = self.debounce_tx.send(());
                }
                _ => {}
            }
        }
        Ok(())
    }

    async fn sync_containers(&self) -> Result<()> {
        let all_containers = self.fetch_all_containers().await?;
        let new_groups = self.group_containers_by_domain(all_containers);

        let current_groups = self.current_routes.lock().await.clone();
        let changes = self.calculate_changes(&current_groups, &new_groups);

        self.apply_changes(changes).await?;
        *self.current_routes.lock().await = new_groups;

        Ok(())
    }

    async fn fetch_all_containers(&self) -> Result<Vec<WorkerContainer>> {
        let tasks: Vec<_> = self
            .config
            .worker_nodes
            .iter()
            .map(|node| self.fetch_containers_from_node(node.clone()))
            .collect();

        let results = futures_util::future::join_all(tasks).await;
        let mut all_containers = Vec::new();

        for (idx, result) in results.into_iter().enumerate() {
            match result {
                Ok(containers) => {
                    let worker = &self.config.worker_nodes[idx];
                    for container in containers {
                        all_containers.push(WorkerContainer {
                            container,
                            worker_node: worker.clone(),
                        });
                    }
                }
                Err(e) => warn!("Worker {} failed: {}", self.config.worker_nodes[idx], e),
            }
        }
        Ok(all_containers)
    }

    async fn fetch_containers_from_node(&self, worker_node: String) -> Result<Vec<Container>> {
        let url = format!("{}/v5.0.0/libpod/containers/json", worker_node);
        let response = self.client.get(&url).send().await?;
        let containers: Vec<Container> = response.json().await?;
        Ok(containers)
    }

    fn group_containers_by_domain(
        &self,
        containers: Vec<WorkerContainer>,
    ) -> HashMap<String, DomainGroup> {
        let mut groups: HashMap<String, Vec<WorkerContainer>> = HashMap::new();

        for container in containers {
            if container.is_proxy_eligible() {
                if let Some(domain) = container.proxy_domain() {
                    groups
                        .entry(domain.to_string())
                        .or_default()
                        .push(container);
                }
            }
        }

        let mut domain_groups = HashMap::new();
        for (domain, containers) in groups {
            let mut upstreams = Vec::new();
            for container in &containers {
                if let Ok(dial) = container.upstream_dial() {
                    upstreams.push(dial);
                }
            }

            if !upstreams.is_empty() {
                upstreams.sort();
                let headers = HeaderConfig::from_labels(&containers[0].container.labels);
                let tls = containers[0].tls_config();

                domain_groups.insert(
                    domain.clone(),
                    DomainGroup {
                        domain: domain.clone(),
                        upstreams,
                        headers,
                        tls,
                    },
                );
            }
        }

        domain_groups
    }

    fn calculate_changes(
        &self,
        current: &HashMap<String, DomainGroup>,
        new: &HashMap<String, DomainGroup>,
    ) -> HashMap<String, ChangeType> {
        let mut changes = HashMap::new();
        let current_domains: HashSet<_> = current.keys().cloned().collect();
        let new_domains: HashSet<_> = new.keys().cloned().collect();

        for domain in &new_domains - &current_domains {
            changes.insert(domain, ChangeType::Add);
        }

        for domain in &current_domains - &new_domains {
            changes.insert(domain, ChangeType::Remove);
        }

        for domain in current_domains.intersection(&new_domains) {
            if current[domain] != new[domain] {
                changes.insert(domain.clone(), ChangeType::Update);
            }
        }

        changes
    }

    async fn apply_changes(&self, changes: HashMap<String, ChangeType>) -> Result<()> {
        let current_groups = self.current_routes.lock().await.clone();

        for (domain, change_type) in changes {
            match change_type {
                ChangeType::Remove => {
                    self.remove_caddy_route(&domain).await?;
                    info!("Removed route: {}", domain);
                }
                ChangeType::Add | ChangeType::Update => {
                    if let Some(group) = current_groups.get(&domain) {
                        self.create_caddy_route(group).await?;
                        let action = if matches!(change_type, ChangeType::Add) {
                            "Added"
                        } else {
                            "Updated"
                        };
                        info!(
                            "{} route: {} ({} upstreams)",
                            action,
                            domain,
                            group.upstreams.len()
                        );
                    }
                }
            }
        }
        Ok(())
    }

    async fn create_caddy_route(&self, group: &DomainGroup) -> Result<()> {
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

    async fn remove_caddy_route(&self, domain: &str) -> Result<()> {
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

    async fn setup_tls(&self, domain: &str, tls: &TlsConfig) -> Result<()> {
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
