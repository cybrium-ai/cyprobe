//! ARP scanner — discovers all devices on a L2 network segment.
//!
//! Sends ARP requests for each IP in the target CIDR and collects responses.
//! Uses pnet for raw packet crafting + sending.

use anyhow::{Context, Result};
use ipnet::Ipv4Net;
use pnet::datalink::{self, Channel, NetworkInterface};
use pnet::packet::arp::{ArpHardwareTypes, ArpOperations, ArpPacket, MutableArpPacket};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::packet::{MutablePacket, Packet};
use pnet::util::MacAddr;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};
use tokio::time::{sleep, Duration};

/// ARP scan a CIDR range. Returns map of IP → MAC address.
pub async fn scan(
    interface_name: &str,
    targets: &str,
    timeout_ms: u64,
) -> Result<HashMap<Ipv4Addr, String>> {
    let interfaces = datalink::interfaces();
    let interface = interfaces
        .iter()
        .find(|iface| iface.name == interface_name)
        .context(format!("Interface '{}' not found", interface_name))?
        .clone();

    let source_ip = interface
        .ips
        .iter()
        .find_map(|ip| match ip.ip() {
            std::net::IpAddr::V4(v4) => Some(v4),
            _ => None,
        })
        .context("No IPv4 address on interface")?;

    let source_mac = interface
        .mac
        .context("No MAC address on interface")?;

    // Parse target CIDR
    let hosts: Vec<Ipv4Addr> = if let Ok(net) = targets.parse::<Ipv4Net>() {
        net.hosts().collect()
    } else {
        vec![targets.parse::<Ipv4Addr>().context("Invalid target IP/CIDR")?]
    };

    let results: Arc<Mutex<HashMap<Ipv4Addr, String>>> = Arc::new(Mutex::new(HashMap::new()));

    // Open the datalink channel
    let (mut tx, mut rx) = match datalink::channel(&interface, Default::default())? {
        Channel::Ethernet(tx, rx) => (tx, rx),
        _ => anyhow::bail!("Unsupported channel type"),
    };

    // Spawn receiver in background
    let results_clone = results.clone();
    let recv_handle = std::thread::spawn(move || {
        let deadline = std::time::Instant::now() + std::time::Duration::from_millis(timeout_ms + 1000);
        while std::time::Instant::now() < deadline {
            match rx.next() {
                Ok(packet) => {
                    if let Some(ethernet) = EthernetPacket::new(packet) {
                        if ethernet.get_ethertype() == EtherTypes::Arp {
                            if let Some(arp) = ArpPacket::new(ethernet.payload()) {
                                if arp.get_operation() == ArpOperations::Reply {
                                    let sender_ip = arp.get_sender_proto_addr();
                                    let sender_mac = arp.get_sender_hw_addr();
                                    let mac_str = format!(
                                        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                                        sender_mac.0, sender_mac.1, sender_mac.2,
                                        sender_mac.3, sender_mac.4, sender_mac.5,
                                    );
                                    results_clone.lock().unwrap().insert(sender_ip, mac_str);
                                }
                            }
                        }
                    }
                }
                Err(_) => break,
            }
        }
    });

    // Send ARP requests
    let total = hosts.len();
    for (i, target_ip) in hosts.iter().enumerate() {
        if i % 50 == 0 {
            eprint!("\r  ARP scanning: {}/{} hosts...", i, total);
        }

        let mut ethernet_buf = [0u8; 42]; // 14 (eth) + 28 (arp)
        let mut ethernet = MutableEthernetPacket::new(&mut ethernet_buf).unwrap();

        ethernet.set_destination(MacAddr::broadcast());
        ethernet.set_source(source_mac);
        ethernet.set_ethertype(EtherTypes::Arp);

        let mut arp_buf = [0u8; 28];
        let mut arp = MutableArpPacket::new(&mut arp_buf).unwrap();

        arp.set_hardware_type(ArpHardwareTypes::Ethernet);
        arp.set_protocol_type(EtherTypes::Ipv4);
        arp.set_hw_addr_len(6);
        arp.set_proto_addr_len(4);
        arp.set_operation(ArpOperations::Request);
        arp.set_sender_hw_addr(source_mac);
        arp.set_sender_proto_addr(source_ip);
        arp.set_target_hw_addr(MacAddr::zero());
        arp.set_target_proto_addr(*target_ip);

        ethernet.set_payload(arp.packet());

        tx.send_to(ethernet.packet(), None);

        // Small delay between packets to avoid flooding
        if i % 10 == 0 {
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
    }

    eprintln!("\r  ARP scanning: {}/{} hosts — waiting for responses...", total, total);

    // Wait for responses
    std::thread::sleep(std::time::Duration::from_millis(timeout_ms));

    // Stop receiver
    drop(recv_handle);

    let final_results = results.lock().unwrap().clone();
    Ok(final_results)
}
