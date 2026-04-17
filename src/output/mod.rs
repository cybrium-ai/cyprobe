use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::Write;
use std::str::FromStr;

use crate::protocols::OtAsset;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Format {
    Json,
    Sarif,
    Text,
}

impl FromStr for Format {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "json" => Ok(Self::Json),
            "sarif" => Ok(Self::Sarif),
            "text" => Ok(Self::Text),
            _ => Err(format!("unknown format: {s}")),
        }
    }
}

impl std::fmt::Display for Format {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Json => write!(f, "json"),
            Self::Sarif => write!(f, "sarif"),
            Self::Text => write!(f, "text"),
        }
    }
}

pub fn write_assets(assets: &[OtAsset], format: Format, path: Option<&str>) -> Result<()> {
    let output = match format {
        Format::Json => serde_json::to_string_pretty(assets)?,
        Format::Text => format_text(assets),
        Format::Sarif => format_sarif(assets),
    };

    match path {
        Some(p) => fs::write(p, &output)?,
        None => std::io::stdout().write_all(output.as_bytes())?,
    }
    Ok(())
}

fn format_text(assets: &[OtAsset]) -> String {
    let mut out = String::new();
    out.push_str(&format!("\ncyprobe — {} device(s) discovered\n", assets.len()));
    out.push_str(&"─".repeat(72));
    out.push('\n');
    for a in assets {
        out.push_str(&format!(
            "  {:?}  {:>15}:{:<5}  {:?}  unit={}  vendor={}\n",
            a.kind,
            a.ip,
            a.port,
            a.protocol,
            a.unit_id.map(|u| u.to_string()).unwrap_or_default(),
            a.vendor.as_deref().unwrap_or("unknown"),
        ));
    }
    out.push_str(&"─".repeat(72));
    out.push('\n');
    out
}

fn format_sarif(assets: &[OtAsset]) -> String {
    let results: Vec<serde_json::Value> = assets
        .iter()
        .map(|a| {
            serde_json::json!({
                "ruleId": format!("OT-DISCOVERY-{:?}", a.protocol).to_uppercase(),
                "level": "note",
                "message": {
                    "text": format!(
                        "{:?} device at {}:{} ({})",
                        a.kind,
                        a.ip,
                        a.port,
                        a.vendor.as_deref().unwrap_or("unknown vendor")
                    )
                },
                "locations": [{
                    "physicalLocation": {
                        "address": { "absoluteAddress": 0 },
                        "artifactLocation": { "uri": format!("{}:{}", a.ip, a.port) }
                    }
                }]
            })
        })
        .collect();

    let sarif = serde_json::json!({
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "cyprobe",
                    "version": env!("CARGO_PKG_VERSION"),
                    "informationUri": "https://github.com/cybrium-ai/cyprobe"
                }
            },
            "results": results
        }]
    });

    serde_json::to_string_pretty(&sarif).unwrap_or_default()
}

pub async fn upload(file: &str, platform: &str, token: &str) -> Result<()> {
    let content = fs::read_to_string(file)?;
    let assets: Vec<OtAsset> = serde_json::from_str(&content)?;

    let client = reqwest::Client::new();
    let url = format!("{}/api/inventory/ingest/ot/", platform.trim_end_matches('/'));

    let resp = client
        .post(&url)
        .bearer_auth(token)
        .json(&assets)
        .send()
        .await?;

    if resp.status().is_success() {
        eprintln!("uploaded {} assets to {}", assets.len(), platform);
    } else {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        anyhow::bail!("upload failed: {} — {}", status, body);
    }
    Ok(())
}
