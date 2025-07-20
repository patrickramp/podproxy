mod config_cli;
mod sync;

use config_cli::Config;
use sync::SyncService;

use anyhow::Result;
use clap::Parser;



#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let config = Config::parse();

    if config.worker_nodes.is_empty() {
        return Err(anyhow::anyhow!("No worker nodes specified"));
    }

    tokio::spawn(run_health_server(config.health_port));

    let service = SyncService::new(config)?;
    service.run().await
}
async fn run_health_server(port: u16) {
    use warp::Filter;

    let health = warp::path("health").map(|| "OK");
    let ready = warp::path("ready").map(|| "OK");

    warp::serve(health.or(ready))
        .run(([0, 0, 0, 0], port))
        .await;
}
