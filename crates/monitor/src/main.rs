//! Maintenance monitor daemon for GCP Confidential VM nodes.
//!
//! Polls the GCP metadata endpoint for scheduled maintenance events and
//! sends webhook alerts when host maintenance is detected. This is
//! critical for Confidential VM nodes because `TERMINATE_ON_HOST_MAINTENANCE`
//! means the VM will be destroyed — all in-memory key material is lost and
//! re-sealing + redeployment is required.
//!
//! Usage:
//!   toprf-monitor [OPTIONS]
//!
//! Options:
//!   --webhook-url <URL>     Webhook URL for alerts (also: WEBHOOK_URL env var)
//!   --poll-interval <SECS>  Poll interval in seconds (default: 60)
//!   --node-id <ID>          Node identifier for alert messages
//!   --help                  Show help
//!
//! Environment:
//!   WEBHOOK_URL       Webhook URL for alerts
//!   NODE_ID           Node identifier
//!   POLL_INTERVAL     Poll interval in seconds

use std::env;
use std::time::Duration;

use tracing::{debug, info, warn, error};

const GCP_MAINTENANCE_URL: &str =
    "http://metadata.google.internal/computeMetadata/v1/instance/maintenance-event";

// -- Types --

#[derive(Debug, Clone, PartialEq)]
enum MaintenanceStatus {
    None,
    TerminateOnHostMaintenance,
    Unknown(String),
}

struct MonitorConfig {
    webhook_url: Option<String>,
    poll_interval: Duration,
    node_id: String,
}

// -- GCP metadata polling --

async fn check_maintenance(client: &reqwest::Client) -> Result<MaintenanceStatus, String> {
    let resp = client
        .get(GCP_MAINTENANCE_URL)
        .header("Metadata-Flavor", "Google")
        .timeout(Duration::from_secs(5))
        .send()
        .await
        .map_err(|e| format!("metadata request failed: {e}"))?;

    let body = resp
        .text()
        .await
        .map_err(|e| format!("failed to read response: {e}"))?;
    let trimmed = body.trim();

    match trimmed {
        "NONE" => Ok(MaintenanceStatus::None),
        "TERMINATE_ON_HOST_MAINTENANCE" => Ok(MaintenanceStatus::TerminateOnHostMaintenance),
        other => Ok(MaintenanceStatus::Unknown(other.to_string())),
    }
}

// -- Webhook alerting --

async fn send_webhook_alert(
    client: &reqwest::Client,
    webhook_url: &str,
    node_id: &str,
    status: &MaintenanceStatus,
) {
    let message = match status {
        MaintenanceStatus::TerminateOnHostMaintenance => {
            format!(
                "TOPRF Node {node_id}: HOST MAINTENANCE SCHEDULED \
                 — VM will be terminated. Key material will be lost. \
                 Re-seal and redeploy required."
            )
        }
        MaintenanceStatus::Unknown(s) => {
            format!("TOPRF Node {node_id}: Unknown maintenance event: {s}")
        }
        MaintenanceStatus::None => return,
    };

    // Send as JSON payload (compatible with Slack, Discord, generic webhooks)
    let payload = serde_json::json!({
        "text": message,
        "node_id": node_id,
        "event": format!("{:?}", status),
        "timestamp": unix_timestamp(),
    });

    match client.post(webhook_url).json(&payload).send().await {
        Ok(resp) if resp.status().is_success() => {
            info!(node_id, "webhook alert sent successfully");
        }
        Ok(resp) => {
            warn!(node_id, status = %resp.status(), "webhook returned non-success");
        }
        Err(e) => {
            error!(node_id, error = %e, "failed to send webhook alert");
        }
    }
}

/// Returns the current Unix timestamp in seconds as a string.
/// Uses `std::time::SystemTime` to avoid pulling in chrono.
fn unix_timestamp() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    format!("{secs}")
}

// -- Webhook URL validation --

fn validate_webhook_url(url: &str) -> Result<(), String> {
    if !url.starts_with("https://") {
        return Err("webhook URL must use https://".into());
    }

    // Block internal/metadata IPs (IPv4 and IPv6)
    let blocked_hosts = [
        "169.254.", "127.", "0.", "10.",
        "172.16.", "172.17.", "172.18.", "172.19.",
        "172.20.", "172.21.", "172.22.", "172.23.",
        "172.24.", "172.25.", "172.26.", "172.27.",
        "172.28.", "172.29.", "172.30.", "172.31.",
        "192.168.", "metadata.google.internal",
        "localhost",
        "[::1]", "[::ffff:", "::1", "::ffff:",
        "fe80:", "fc00:", "fd00:",
    ];

    // Extract host from URL
    let without_scheme = url.strip_prefix("https://").unwrap_or(url);
    let host_port = without_scheme.split('/').next().unwrap_or("");
    // For IPv6 URLs like https://[::1]:8080/path, the host is [::1]
    let host = if host_port.starts_with('[') {
        // IPv6 bracket notation
        host_port.split(']').next().unwrap_or("")
    } else {
        host_port.split(':').next().unwrap_or("")
    };

    for blocked in &blocked_hosts {
        if host.starts_with(blocked) || host == *blocked {
            return Err(format!("webhook URL must not target internal address: {host}"));
        }
    }

    Ok(())
}

// -- Argument parsing --

fn parse_config() -> MonitorConfig {
    let args: Vec<String> = env::args().collect();

    let mut webhook_url: Option<String> = env::var("WEBHOOK_URL").ok();
    let mut poll_interval: u64 = env::var("POLL_INTERVAL")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(60);
    let mut node_id: String = env::var("NODE_ID").unwrap_or_else(|_| "unknown".into());

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--webhook-url" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("Error: --webhook-url requires a value");
                    std::process::exit(1);
                }
                webhook_url = Some(args[i].clone());
            }
            "--poll-interval" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("Error: --poll-interval requires a value");
                    std::process::exit(1);
                }
                poll_interval = args[i].parse().unwrap_or_else(|_| {
                    eprintln!("Error: --poll-interval must be a positive integer");
                    std::process::exit(1);
                });
            }
            "--node-id" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("Error: --node-id requires a value");
                    std::process::exit(1);
                }
                node_id = args[i].clone();
            }
            "--help" | "-h" => {
                eprintln!("Usage: toprf-monitor [OPTIONS]");
                eprintln!();
                eprintln!("Monitors GCP maintenance events for Confidential VM nodes.");
                eprintln!("Sends webhook alerts when host maintenance is scheduled.");
                eprintln!();
                eprintln!("Options:");
                eprintln!("  --webhook-url <URL>     Webhook URL for alerts (also: WEBHOOK_URL env var)");
                eprintln!("  --poll-interval <SECS>  Poll interval in seconds (default: 60)");
                eprintln!("  --node-id <ID>          Node identifier for alert messages");
                eprintln!("  -h, --help              Show this help");
                eprintln!();
                eprintln!("Environment:");
                eprintln!("  WEBHOOK_URL       Webhook URL for alerts");
                eprintln!("  NODE_ID           Node identifier");
                eprintln!("  POLL_INTERVAL     Poll interval in seconds");
                std::process::exit(0);
            }
            other => {
                eprintln!("Unknown argument: {other}");
                std::process::exit(1);
            }
        }
        i += 1;
    }

    if poll_interval == 0 {
        eprintln!("Error: poll interval must be > 0");
        std::process::exit(1);
    }

    MonitorConfig {
        webhook_url,
        poll_interval: Duration::from_secs(poll_interval),
        node_id,
    }
}

// -- Main --

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let config = parse_config();

    // Validate webhook URL at startup before entering the main loop
    if let Some(ref url) = config.webhook_url {
        if let Err(e) = validate_webhook_url(url) {
            eprintln!("Error: invalid webhook URL: {e}");
            std::process::exit(1);
        }
    }

    info!(
        node_id = %config.node_id,
        poll_interval_secs = config.poll_interval.as_secs(),
        webhook_configured = config.webhook_url.is_some(),
        "starting toprf-monitor"
    );

    if config.webhook_url.is_none() {
        warn!("no webhook URL configured — alerts will only be logged");
    }

    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(10))
        .build()
        .expect("failed to build HTTP client");
    let mut last_status = MaintenanceStatus::None;

    // Set up SIGTERM handler for graceful shutdown
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .expect("failed to register SIGTERM handler");

    loop {
        tokio::select! {
            _ = sigterm.recv() => {
                info!(node_id = %config.node_id, "received SIGTERM, shutting down");
                break;
            }
            _ = tokio::signal::ctrl_c() => {
                info!(node_id = %config.node_id, "received SIGINT, shutting down");
                break;
            }
            _ = tokio::time::sleep(config.poll_interval) => {
                match check_maintenance(&client).await {
                    Ok(status) => {
                        debug!(
                            node_id = %config.node_id,
                            status = ?status,
                            "maintenance check complete"
                        );

                        if status != last_status {
                            match &status {
                                MaintenanceStatus::None => {
                                    info!(
                                        node_id = %config.node_id,
                                        "maintenance status cleared"
                                    );
                                }
                                MaintenanceStatus::TerminateOnHostMaintenance => {
                                    warn!(
                                        node_id = %config.node_id,
                                        "HOST MAINTENANCE SCHEDULED — VM will be terminated"
                                    );
                                }
                                MaintenanceStatus::Unknown(ref s) => {
                                    warn!(
                                        node_id = %config.node_id,
                                        event = %s,
                                        "unknown maintenance event detected"
                                    );
                                }
                            }

                            // Send webhook alert for non-None transitions
                            if status != MaintenanceStatus::None {
                                if let Some(ref url) = config.webhook_url {
                                    send_webhook_alert(&client, url, &config.node_id, &status)
                                        .await;
                                }
                            }

                            last_status = status;
                        }
                    }
                    Err(e) => {
                        error!(
                            node_id = %config.node_id,
                            error = %e,
                            "failed to check maintenance status"
                        );
                    }
                }
            }
        }
    }

    info!(node_id = %config.node_id, "toprf-monitor stopped");
}
