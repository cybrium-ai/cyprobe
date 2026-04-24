//! Network template loader — reads Nuclei-converted TCP templates from YAML.

use serde::Deserialize;
use std::path::Path;
use tracing::{debug, info};

#[derive(Debug, Deserialize, Clone)]
pub struct NetTemplate {
    pub id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub severity: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub cwe: Vec<String>,
    #[serde(default)]
    pub remediation: String,
    /// Ports this template applies to (empty = match all open ports).
    #[serde(default)]
    pub ports: Vec<u16>,
    /// TCP interaction steps.
    #[serde(default)]
    pub steps: Vec<NetStep>,
    /// Matchers for the response.
    #[serde(default)]
    pub matchers: Vec<NetMatcher>,
    #[serde(default = "default_or")]
    pub matchers_condition: String,
}

fn default_or() -> String { "or".into() }

#[derive(Debug, Deserialize, Clone)]
pub struct NetStep {
    /// Data to send (supports \\x hex escapes and \\r\\n).
    #[serde(default)]
    pub data: String,
    /// Bytes to read from response.
    #[serde(default)]
    pub read_size: Option<usize>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct NetMatcher {
    #[serde(rename = "type", default = "default_word")]
    pub matcher_type: String,
    #[serde(default)]
    pub words: Vec<String>,
    #[serde(default)]
    pub regex: Vec<String>,
    #[serde(default)]
    pub binary: Vec<String>,
    #[serde(default)]
    pub negative: bool,
    #[serde(default = "default_or")]
    pub condition: String,
}

fn default_word() -> String { "word".into() }

// ── Embedded templates ───────────────────────────────────────────────────────

/// Core service detection templates compiled into the binary.
const EMBEDDED: &[(&str, &str)] = &[
    ("redis", include_str!("../../net-templates/redis-detect.yaml")),
    ("mongodb", include_str!("../../net-templates/mongodb-detect.yaml")),
    ("mysql", include_str!("../../net-templates/mysql-detect.yaml")),
    ("ftp-anon", include_str!("../../net-templates/ftp-anonymous.yaml")),
    ("ssh-banner", include_str!("../../net-templates/ssh-detect.yaml")),
    ("smtp-open", include_str!("../../net-templates/smtp-open-relay.yaml")),
    ("memcached", include_str!("../../net-templates/memcached-detect.yaml")),
    ("rdp-detect", include_str!("../../net-templates/rdp-detect.yaml")),
    ("telnet-detect", include_str!("../../net-templates/telnet-detect.yaml")),
    ("elasticsearch", include_str!("../../net-templates/elasticsearch-detect.yaml")),
    ("vnc-detect", include_str!("../../net-templates/vnc-detect.yaml")),
    ("postgres-detect", include_str!("../../net-templates/postgres-detect.yaml")),
];

pub fn load_net_templates(extra_dir: Option<&str>) -> Vec<NetTemplate> {
    let mut templates = Vec::new();

    // Embedded
    for (name, yaml) in EMBEDDED {
        match serde_yaml::from_str::<NetTemplate>(yaml) {
            Ok(tpl) => templates.push(tpl),
            Err(e) => debug!(name = name, error = %e, "failed to parse embedded net template"),
        }
    }
    info!(count = templates.len(), "loaded embedded net templates");

    // User directory: ~/.cyprobe/net-templates/
    if let Some(home) = dirs::home_dir() {
        let user_dir = home.join(".cyprobe").join("net-templates");
        let user_tpls = load_from_dir(&user_dir);
        if !user_tpls.is_empty() {
            info!(count = user_tpls.len(), "loaded user net templates");
            templates.extend(user_tpls);
        }
    }

    // Custom directory
    if let Some(dir) = extra_dir {
        let custom_tpls = load_from_dir(Path::new(dir));
        if !custom_tpls.is_empty() {
            info!(count = custom_tpls.len(), dir = dir, "loaded custom net templates");
            templates.extend(custom_tpls);
        }
    }

    templates
}

fn load_from_dir(dir: &Path) -> Vec<NetTemplate> {
    let mut templates = Vec::new();
    if !dir.exists() {
        return templates;
    }
    for path in walkdir(dir) {
        if path.extension().map(|e| e == "yaml" || e == "yml").unwrap_or(false) {
            if let Ok(content) = std::fs::read_to_string(&path) {
                match serde_yaml::from_str::<NetTemplate>(&content) {
                    Ok(tpl) => templates.push(tpl),
                    Err(_) => {}
                }
            }
        }
    }
    templates
}

fn walkdir(dir: &Path) -> Vec<std::path::PathBuf> {
    let mut results = Vec::new();
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                results.extend(walkdir(&path));
            } else {
                results.push(path);
            }
        }
    }
    results
}
