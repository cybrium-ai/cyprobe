//! Network service scanner — TCP template engine for non-HTTP service detection.
//!
//! Loads YAML templates (converted from Nuclei network/ + javascript/ categories)
//! and probes TCP services: Redis, MongoDB, MySQL, FTP, SMTP, Memcached, RDP,
//! SSH, Telnet, backdoors, C2 beacons, JARM fingerprints.
//!
//! Templates define: host, port, data to send, expected response matchers.

pub mod templates;

use anyhow::Result;
use ipnet::Ipv4Net;
use std::net::{Ipv4Addr, SocketAddr};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};
use tracing::{debug, info, warn};

use crate::output::{self, Format};

#[derive(Debug, Clone, serde::Serialize)]
pub struct NetFinding {
    pub id: String,
    pub title: String,
    pub severity: String,
    pub description: String,
    pub host: String,
    pub port: u16,
    pub evidence: String,
    pub tags: Vec<String>,
    pub cwe: Vec<String>,
    pub remediation: String,
}

/// Default ports to scan when no specific port is in the template.
const DEFAULT_SCAN_PORTS: &[u16] = &[
    21,    // FTP
    22,    // SSH
    23,    // Telnet
    25,    // SMTP
    110,   // POP3
    143,   // IMAP
    389,   // LDAP
    443,   // HTTPS
    445,   // SMB
    993,   // IMAPS
    995,   // POP3S
    1433,  // MSSQL
    1521,  // Oracle
    2049,  // NFS
    3306,  // MySQL
    3389,  // RDP
    5432,  // PostgreSQL
    5672,  // AMQP
    5900,  // VNC
    6379,  // Redis
    6380,  // Redis TLS
    8080,  // HTTP alt
    8443,  // HTTPS alt
    9200,  // Elasticsearch
    11211, // Memcached
    27017, // MongoDB
];

pub async fn run(
    targets_str: &str,
    ports_str: Option<&str>,
    templates_dir: Option<&str>,
    rate_limit: u32,
    connect_timeout_ms: u64,
    format: Format,
    output_path: Option<&str>,
) -> Result<()> {
    let hosts = parse_targets(targets_str)?;
    let ports = parse_ports(ports_str);
    let delay = Duration::from_millis(1000 / rate_limit.max(1) as u64);
    let connect_timeout = Duration::from_millis(connect_timeout_ms);

    // Load templates
    let tpls = templates::load_net_templates(templates_dir);
    info!(
        hosts = hosts.len(),
        ports = ports.len(),
        templates = tpls.len(),
        "starting network scan"
    );

    let mut findings: Vec<NetFinding> = Vec::new();
    let mut scanned = 0usize;
    let total = hosts.len() * ports.len();

    for host in &hosts {
        for port in &ports {
            scanned += 1;
            if scanned % 20 == 0 {
                eprint!("\r  Progress: {}/{} hosts:ports ({} findings)...", scanned, total, findings.len());
            }

            let addr = SocketAddr::new((*host).into(), *port);

            // Quick connect check
            let stream = match timeout(connect_timeout, TcpStream::connect(addr)).await {
                Ok(Ok(s)) => s,
                _ => continue, // Port closed or timeout
            };

            debug!(host = %host, port = port, "port open");

            // Run banner grab
            let banner = grab_banner(stream, connect_timeout).await;

            // Match templates against this host:port + banner
            for tpl in &tpls {
                // Check if template applies to this port
                if !tpl.ports.is_empty() && !tpl.ports.contains(port) {
                    continue;
                }

                if let Some(finding) = execute_template(host, *port, &tpl, &banner, connect_timeout).await {
                    findings.push(finding);
                }
            }

            tokio::time::sleep(delay).await;
        }
    }

    eprintln!("\r  Scan complete: {}/{} probed, {} findings found     ", scanned, total, findings.len());

    // Output
    let json = serde_json::to_string_pretty(&findings)?;
    if let Some(path) = output_path {
        std::fs::write(path, &json)?;
        info!(path = path, "results written");
    } else {
        println!("{}", json);
    }

    Ok(())
}

async fn grab_banner(mut stream: TcpStream, timeout_dur: Duration) -> String {
    let mut buf = vec![0u8; 4096];
    match timeout(timeout_dur, stream.read(&mut buf)).await {
        Ok(Ok(n)) if n > 0 => String::from_utf8_lossy(&buf[..n]).to_string(),
        _ => String::new(),
    }
}

async fn execute_template(
    host: &Ipv4Addr,
    port: u16,
    tpl: &templates::NetTemplate,
    banner: &str,
    connect_timeout: Duration,
) -> Option<NetFinding> {
    let addr = SocketAddr::new((*host).into(), port);

    // If template has data to send, connect and send it
    let response = if tpl.steps.is_empty() {
        // Just match against banner
        banner.to_string()
    } else {
        let mut full_response = String::new();
        for step in &tpl.steps {
            let mut stream = match timeout(connect_timeout, TcpStream::connect(addr)).await {
                Ok(Ok(s)) => s,
                _ => return None,
            };

            // Send data
            if !step.data.is_empty() {
                let data = unescape_hex(&step.data);
                if stream.write_all(&data).await.is_err() {
                    return None;
                }
            }

            // Read response
            let read_size = step.read_size.unwrap_or(4096);
            let mut buf = vec![0u8; read_size];
            match timeout(connect_timeout, stream.read(&mut buf)).await {
                Ok(Ok(n)) if n > 0 => {
                    full_response.push_str(&String::from_utf8_lossy(&buf[..n]));
                }
                _ => {}
            }
        }
        full_response
    };

    // Evaluate matchers
    let matched = evaluate_matchers(&tpl.matchers, &response, &tpl.matchers_condition);

    if matched {
        let evidence = if response.len() > 200 {
            format!("{}...", &response[..200])
        } else if response.is_empty() {
            "Connection accepted (no banner)".to_string()
        } else {
            response.chars().filter(|c| !c.is_control() || *c == '\n').collect()
        };

        Some(NetFinding {
            id: tpl.id.clone(),
            title: tpl.name.clone(),
            severity: tpl.severity.clone(),
            description: tpl.description.clone(),
            host: host.to_string(),
            port,
            evidence,
            tags: tpl.tags.clone(),
            cwe: tpl.cwe.clone(),
            remediation: tpl.remediation.clone(),
        })
    } else {
        None
    }
}

fn evaluate_matchers(matchers: &[templates::NetMatcher], response: &str, condition: &str) -> bool {
    if matchers.is_empty() {
        return false;
    }

    let results: Vec<bool> = matchers.iter().map(|m| {
        let matched = match m.matcher_type.as_str() {
            "word" => {
                let word_results: Vec<bool> = m.words.iter().map(|w| {
                    response.to_lowercase().contains(&w.to_lowercase())
                }).collect();
                match m.condition.as_str() {
                    "and" => word_results.iter().all(|&r| r),
                    _ => word_results.iter().any(|&r| r),
                }
            }
            "regex" => {
                m.regex.iter().any(|pattern| {
                    regex::Regex::new(pattern).map(|re| re.is_match(response)).unwrap_or(false)
                })
            }
            "binary" => {
                let response_bytes = response.as_bytes();
                m.binary.iter().any(|hex_str| {
                    if let Ok(bytes) = hex::decode(hex_str.replace(" ", "")) {
                        response_bytes.windows(bytes.len()).any(|w| w == bytes.as_slice())
                    } else {
                        false
                    }
                })
            }
            _ => false,
        };
        if m.negative { !matched } else { matched }
    }).collect();

    match condition {
        "and" => results.iter().all(|&r| r),
        _ => results.iter().any(|&r| r),
    }
}

fn unescape_hex(s: &str) -> Vec<u8> {
    let mut result = Vec::new();
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if i + 3 < bytes.len() && bytes[i] == b'\\' && bytes[i + 1] == b'x' {
            if let Ok(byte) = u8::from_str_radix(&s[i + 2..i + 4], 16) {
                result.push(byte);
                i += 4;
                continue;
            }
        }
        if i + 1 < bytes.len() && bytes[i] == b'\\' {
            match bytes[i + 1] {
                b'r' => { result.push(b'\r'); i += 2; continue; }
                b'n' => { result.push(b'\n'); i += 2; continue; }
                b't' => { result.push(b'\t'); i += 2; continue; }
                b'\\' => { result.push(b'\\'); i += 2; continue; }
                _ => {}
            }
        }
        result.push(bytes[i]);
        i += 1;
    }
    result
}

fn parse_targets(cidr: &str) -> Result<Vec<Ipv4Addr>> {
    if let Ok(net) = cidr.parse::<Ipv4Net>() {
        Ok(net.hosts().collect())
    } else {
        let ip: Ipv4Addr = cidr.parse()?;
        Ok(vec![ip])
    }
}

fn parse_ports(ports_str: Option<&str>) -> Vec<u16> {
    match ports_str {
        Some(s) if !s.is_empty() => {
            s.split(',')
                .filter_map(|p| {
                    let p = p.trim();
                    if let Some((start, end)) = p.split_once('-') {
                        let s: u16 = start.parse().ok()?;
                        let e: u16 = end.parse().ok()?;
                        Some((s..=e).collect::<Vec<u16>>())
                    } else {
                        Some(vec![p.parse().ok()?])
                    }
                })
                .flatten()
                .collect()
        }
        _ => DEFAULT_SCAN_PORTS.to_vec(),
    }
}
