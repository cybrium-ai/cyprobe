//! NetBIOS Name Service — query Windows device hostnames via UDP 137.
//!
//! Sends a NetBIOS Name Query to resolve the device's NetBIOS name.
//! Timeout-safe: returns Err if the device doesn't respond within the timeout.

use anyhow::{Context, Result};
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::time::Duration;

/// Query the NetBIOS name of a device at the given IP.
pub async fn query_name(ip: Ipv4Addr, timeout_ms: u64) -> Result<String> {
    // Run blocking UDP in a spawn_blocking since UdpSocket is sync
    let timeout = timeout_ms;
    tokio::task::spawn_blocking(move || {
        query_name_sync(ip, timeout)
    })
    .await
    .context("NetBIOS task panicked")?
}

fn query_name_sync(ip: Ipv4Addr, timeout_ms: u64) -> Result<String> {
    let socket = UdpSocket::bind("0.0.0.0:0").context("Failed to bind UDP socket")?;
    socket.set_read_timeout(Some(Duration::from_millis(timeout_ms)))?;

    // NetBIOS Name Query packet (Node Status Request)
    // Transaction ID: 0x0001
    // Flags: 0x0000 (query)
    // Questions: 1
    // Name: * (wildcard — encoded as CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA)
    let query: Vec<u8> = vec![
        0x00, 0x01, // Transaction ID
        0x00, 0x00, // Flags: standard query
        0x00, 0x01, // Questions: 1
        0x00, 0x00, // Answer RRs: 0
        0x00, 0x00, // Authority RRs: 0
        0x00, 0x00, // Additional RRs: 0
        // Name: * (wildcard) encoded in NetBIOS encoding
        0x20, // Name length: 32 bytes
        0x43, 0x4B, // CK = * (0x2A → 0x43, 0x4B)
        0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, // padding (null → AA)
        0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
        0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
        0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
        0x00, // Name terminator
        0x00, 0x21, // Type: NBSTAT (Node Status)
        0x00, 0x01, // Class: IN
    ];

    let target = SocketAddr::new(ip.into(), 137);
    socket.send_to(&query, target).context("Failed to send NetBIOS query")?;

    let mut buf = [0u8; 1024];
    let (len, _) = socket.recv_from(&mut buf).context("NetBIOS timeout — no response")?;

    if len < 57 {
        anyhow::bail!("Response too short");
    }

    // Parse the response — find the first name entry
    // Response header: 12 bytes, then name section
    // Skip to the answer section
    let num_names = buf[56] as usize;
    if num_names == 0 {
        anyhow::bail!("No names in response");
    }

    // First name starts at offset 57, each entry is 18 bytes (15 name + 1 suffix + 2 flags)
    let name_start = 57;
    if len < name_start + 18 {
        anyhow::bail!("Truncated name entry");
    }

    // Extract the first 15 bytes as the name, trim trailing spaces
    let name_bytes = &buf[name_start..name_start + 15];
    let name = String::from_utf8_lossy(name_bytes).trim().to_string();

    if name.is_empty() {
        anyhow::bail!("Empty name");
    }

    Ok(name)
}
