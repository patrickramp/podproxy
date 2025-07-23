pub mod service;
mod workers;
mod tls;   
mod caddy; 

use crate::config_cli::Config;

pub use service::SyncService;
use caddy::{HeaderConfig, DomainGroup};
use workers::{WorkerContainer, Container};
use tls::TlsConfig;