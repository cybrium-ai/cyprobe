//! Network device discovery — ARP scanning, MAC OUI lookup, NetBIOS name resolution.
//!
//! Usage:
//!   cyprobe discover --interface eth0 --targets 10.0.1.0/24
//!
//! Discovers all devices on the L2 segment, resolves vendor from MAC OUI,
//! and queries NetBIOS for Windows hostname.

pub mod arp;
pub mod oui;
pub mod netbios;

use anyhow::Result;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use tokio::time::{sleep, Duration};
use tracing::{info, warn};

use crate::output::{self, Format};

#[derive(Debug, Clone, serde::Serialize)]
pub struct DiscoveredDevice {
    pub ip: String,
    pub mac: String,
    pub vendor: String,
    pub hostname: Option<String>,
    pub netbios_name: Option<String>,
    pub device_type: String,  // "unknown", "workstation", "server", "medical", "plc", "printer", "network"
    pub purdue_level: Option<u8>,
    pub protocols: Vec<String>,
    pub first_seen: String,
}

pub async fn run(
    interface: &str,
    targets: &str,
    timeout_ms: u64,
    enable_netbios: bool,
    format: Format,
    output_path: Option<&str>,
) -> Result<()> {
    info!("Starting network discovery on interface {}", interface);

    // Step 1: ARP scan
    info!("Phase 1: ARP scanning {}...", targets);
    let arp_results = arp::scan(interface, targets, timeout_ms).await?;
    info!("{} devices found via ARP", arp_results.len());

    // Step 2: Resolve MAC → vendor via OUI database
    info!("Phase 2: Resolving MAC vendors...");
    let mut devices: Vec<DiscoveredDevice> = Vec::new();

    for (ip, mac) in &arp_results {
        let vendor = oui::lookup(mac);
        let device_type = oui::classify_vendor(&vendor);
        let purdue = oui::estimate_purdue_level(&vendor, &device_type);

        devices.push(DiscoveredDevice {
            ip: ip.to_string(),
            mac: mac.clone(),
            vendor: vendor.clone(),
            hostname: None,
            netbios_name: None,
            device_type,
            purdue_level: purdue,
            protocols: Vec::new(),
            first_seen: chrono::Utc::now().to_rfc3339(),
        });
    }

    // Step 3: NetBIOS name resolution
    if enable_netbios {
        info!("Phase 3: NetBIOS name resolution...");
        for device in &mut devices {
            if let Ok(ip) = device.ip.parse::<Ipv4Addr>() {
                match netbios::query_name(ip, timeout_ms).await {
                    Ok(name) => {
                        device.netbios_name = Some(name.clone());
                        device.hostname = Some(name);
                        if device.device_type == "unknown" {
                            device.device_type = "workstation".to_string();
                        }
                    }
                    Err(_) => {}
                }
            }
        }
        let resolved = devices.iter().filter(|d| d.netbios_name.is_some()).count();
        info!("{} NetBIOS names resolved", resolved);
    }

    // Sort by IP
    devices.sort_by(|a, b| {
        let a_ip: Ipv4Addr = a.ip.parse().unwrap_or(Ipv4Addr::UNSPECIFIED);
        let b_ip: Ipv4Addr = b.ip.parse().unwrap_or(Ipv4Addr::UNSPECIFIED);
        a_ip.cmp(&b_ip)
    });

    // Print summary
    eprintln!();
    eprintln!("  \x1b[1m{} devices discovered\x1b[0m", devices.len());
    let vendors: HashMap<&str, usize> = devices.iter().fold(HashMap::new(), |mut acc, d| {
        *acc.entry(d.vendor.as_str()).or_insert(0) += 1;
        acc
    });
    let mut vendor_list: Vec<_> = vendors.into_iter().collect();
    vendor_list.sort_by(|a, b| b.1.cmp(&a.1));
    for (vendor, count) in vendor_list.iter().take(10) {
        eprintln!("    \x1b[2m{}: {}\x1b[0m", vendor, count);
    }
    eprintln!();

    // Output
    let json = serde_json::to_string_pretty(&devices)?;
    if let Some(path) = output_path {
        std::fs::write(path, &json)?;
        info!(path = path, "results written");
    } else {
        println!("{}", json);
    }

    Ok(())
}
