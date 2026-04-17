use anyhow::Result;
use ipnet::Ipv4Net;
use std::net::{Ipv4Addr, SocketAddr};
use tokio::time::{sleep, Duration};
use tracing::{info, warn};

use crate::output::{self, Format};
use crate::protocols::{modbus, OtAsset, Protocol};

struct ProbeTarget {
    ip: Ipv4Addr,
    protocol: Protocol,
}

fn parse_targets(cidr: &str) -> Result<Vec<Ipv4Addr>> {
    if let Ok(net) = cidr.parse::<Ipv4Net>() {
        Ok(net.hosts().collect())
    } else {
        let ip: Ipv4Addr = cidr.parse()?;
        Ok(vec![ip])
    }
}

fn parse_protocols(input: &str) -> Vec<Protocol> {
    input
        .split(',')
        .filter_map(|s| match s.trim() {
            "modbus" => Some(Protocol::ModbusTcp),
            "s7" => Some(Protocol::S7comm),
            "opcua" => Some(Protocol::OpcUa),
            "bacnet" => Some(Protocol::BacnetIp),
            "enip" => Some(Protocol::EthernetIp),
            "iec104" => Some(Protocol::Iec104),
            "dnp3" => Some(Protocol::Dnp3),
            _ => {
                warn!(protocol = s, "unknown protocol, skipping");
                None
            }
        })
        .collect()
}

pub async fn run(
    targets_str: &str,
    protocols_str: &str,
    rate_limit: u32,
    format: Format,
    output_path: Option<&str>,
) -> Result<()> {
    let hosts = parse_targets(targets_str)?;
    let protocols = parse_protocols(protocols_str);
    let delay = Duration::from_millis(1000 / rate_limit.max(1) as u64);

    info!(
        hosts = hosts.len(),
        protocols = protocols.len(),
        rate = rate_limit,
        "starting active probe"
    );

    let mut targets: Vec<ProbeTarget> = Vec::new();
    for ip in &hosts {
        for proto in &protocols {
            targets.push(ProbeTarget {
                ip: *ip,
                protocol: proto.clone(),
            });
        }
    }

    let mut discovered: Vec<OtAsset> = Vec::new();

    for target in &targets {
        let port = target.protocol.default_port();
        let addr = SocketAddr::new(target.ip.into(), port);

        match &target.protocol {
            Protocol::ModbusTcp => match modbus::probe_device(addr).await {
                Ok(asset) => {
                    info!(
                        ip = %asset.ip,
                        vendor = asset.vendor.as_deref().unwrap_or("unknown"),
                        "modbus device found"
                    );
                    discovered.push(asset);
                }
                Err(e) => {
                    tracing::debug!(ip = %target.ip, error = %e, "modbus probe failed");
                }
            },
            // Phase 2 stubs — implemented once the Modbus path is proven
            Protocol::S7comm => {
                tracing::debug!(ip = %target.ip, "S7comm probe not yet implemented");
            }
            Protocol::OpcUa => {
                tracing::debug!(ip = %target.ip, "OPC UA probe not yet implemented");
            }
            Protocol::BacnetIp => {
                tracing::debug!(ip = %target.ip, "BACnet probe not yet implemented");
            }
            Protocol::EthernetIp => {
                tracing::debug!(ip = %target.ip, "EtherNet/IP probe not yet implemented");
            }
            Protocol::Iec104 => {
                tracing::debug!(ip = %target.ip, "IEC 104 probe not yet implemented");
            }
            _ => {}
        }

        sleep(delay).await;
    }

    info!(count = discovered.len(), "active probe complete");
    output::write_assets(&discovered, format, output_path)?;
    Ok(())
}
