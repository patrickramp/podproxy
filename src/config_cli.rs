// ============================================================================
// Configuration and CLI
// ============================================================================

use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "podproxy", about = "Dynamic Caddy load balancer for Podman clusters")]
pub struct Config {
    /// Comma-separated list of Podman API endpoints
    #[arg(long, env = "WORKER_NODES", value_delimiter = ',')]
    pub worker_nodes: Vec<String>,

    /// Caddy Admin API endpoint
    #[arg(long, env = "CADDY_ADMIN", default_value = "http://localhost:2019")]
    caddy_admin: String,

    /// Health check server port
    #[arg(long, env = "HEALTH_PORT", default_value = "8080")]
    pub health_port: u16,

    /// Maximum retry attempts for failed operations
    #[arg(long, env = "MAX_RETRIES", default_value = "5")]
    pub max_retries: u32,

    /// Load balancing policy: round_robin, least_conn, ip_hash, random, etc.
    #[arg(long, env = "LOAD_BALANCE_POLICY", default_value = "round_robin")]
    lb_policy: String,

    /// Event stream reconnection timeout (seconds)
    #[arg(long, env = "RECONNECT_TIMEOUT", default_value = "30")]
    pub reconnect_timeout: u64,

    /// Event stream debouncing interval (milliseconds)
    #[arg(long, env = "DEBOUNCE_MS", default_value = "2000")]
    pub debounce_ms: u64,
}
