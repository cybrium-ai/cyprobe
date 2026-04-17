use anyhow::{Context, Result};
use pnet::datalink::{self, Channel, NetworkInterface};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::Packet;
use std::collections::HashMap;
use std::time::{Duration, Instant};
use tracing::{debug, info, warn};

use crate::output::{self, Format};
use crate::protocols::{self, modbus, dnp3, OtAsset, Protocol};

type AssetKey = (String, u16, Protocol);

pub fn list_interfaces() {
    let interfaces = datalink::interfaces();
    if interfaces.is_empty() {
        eprintln!("No network interfaces found. Try running with elevated privileges.");
        return;
    }
    println!("{:<20} {:<18} {:<6} {}", "NAME", "IP", "UP", "FLAGS");
    for iface in interfaces {
        let ip = iface
            .ips
            .first()
            .map(|n| n.ip().to_string())
            .unwrap_or_default();
        let up = if iface.is_up() { "yes" } else { "no" };
        let flags: Vec<&str> = [
            iface.is_loopback().then_some("lo"),
            iface.is_point_to_point().then_some("p2p"),
            iface.is_broadcast().then_some("bcast"),
            iface.is_multicast().then_some("mcast"),
        ]
        .into_iter()
        .flatten()
        .collect();
        println!("{:<20} {:<18} {:<6} {}", iface.name, ip, up, flags.join(","));
    }
}

fn find_interface(name: &str) -> Result<NetworkInterface> {
    datalink::interfaces()
        .into_iter()
        .find(|i| i.name == name)
        .context(format!("interface '{}' not found", name))
}

pub async fn run(
    interface: &str,
    duration_secs: u64,
    format: Format,
    output_path: Option<&str>,
) -> Result<()> {
    let iface = find_interface(interface)?;
    info!(interface = %iface.name, duration = duration_secs, "starting passive capture");

    let (_, mut rx) = match datalink::channel(&iface, Default::default())? {
        Channel::Ethernet(tx, rx) => (tx, rx),
        _ => anyhow::bail!("unsupported channel type for {}", interface),
    };

    let mut assets: HashMap<AssetKey, OtAsset> = HashMap::new();
    let start = Instant::now();
    let deadline = if duration_secs == 0 {
        None
    } else {
        Some(start + Duration::from_secs(duration_secs))
    };

    info!("listening for OT protocol traffic (Modbus TCP, DNP3)…");

    loop {
        if let Some(d) = deadline {
            if Instant::now() >= d {
                break;
            }
        }

        let packet = match rx.next() {
            Ok(p) => p,
            Err(e) => {
                warn!(error = %e, "capture error");
                continue;
            }
        };

        let eth = match EthernetPacket::new(packet) {
            Some(e) => e,
            None => continue,
        };

        if eth.get_ethertype() != EtherTypes::Ipv4 {
            continue;
        }

        let ipv4 = match Ipv4Packet::new(eth.payload()) {
            Some(p) => p,
            None => continue,
        };

        if ipv4.get_next_level_protocol() != IpNextHeaderProtocols::Tcp {
            continue;
        }

        let tcp = match TcpPacket::new(ipv4.payload()) {
            Some(t) => t,
            None => continue,
        };

        let payload = tcp.payload();
        if payload.is_empty() {
            continue;
        }

        let src_ip = ipv4.get_source().to_string();
        let dst_ip = ipv4.get_destination().to_string();
        let src_port = tcp.get_source();
        let dst_port = tcp.get_destination();
        let now = chrono::Utc::now().to_rfc3339();

        // Modbus TCP
        if let Some((unit_id, fc)) = modbus::classify_packet(src_port, dst_port, payload) {
            let (device_ip, device_port) = if dst_port == 502 {
                (dst_ip.clone(), dst_port)
            } else {
                (src_ip.clone(), src_port)
            };
            let key = (device_ip.clone(), device_port, Protocol::ModbusTcp);
            let asset = assets.entry(key).or_insert_with(|| OtAsset {
                kind: protocols::AssetKind::Plc,
                ip: device_ip,
                port: device_port,
                protocol: Protocol::ModbusTcp,
                unit_id: Some(unit_id as u16),
                vendor: None,
                product: None,
                firmware: None,
                serial: None,
                first_seen: now.clone(),
                last_seen: now.clone(),
                passive_only: true,
            });
            asset.last_seen = now.clone();
            debug!(ip = %asset.ip, unit_id, fc, "modbus traffic");
        }

        // DNP3
        if let Some((source_addr, _dest_addr)) = dnp3::classify_packet(src_port, dst_port, payload)
        {
            let (device_ip, device_port) = if dst_port == 20000 {
                (dst_ip.clone(), dst_port)
            } else {
                (src_ip.clone(), src_port)
            };
            let key = (device_ip.clone(), device_port, Protocol::Dnp3);
            let asset = assets
                .entry(key)
                .or_insert_with(|| dnp3::asset_from_passive(&device_ip, device_port, source_addr));
            asset.last_seen = now.clone();
            debug!(ip = %asset.ip, dnp3_addr = source_addr, "DNP3 traffic");
        }
    }

    let discovered: Vec<OtAsset> = assets.into_values().collect();
    info!(count = discovered.len(), "passive capture complete");

    output::write_assets(&discovered, format, output_path)?;
    Ok(())
}
