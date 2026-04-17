use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use tracing::info;

use crate::output::Format;
use crate::protocols::OtAsset;

#[derive(Debug, Deserialize)]
pub struct OtRule {
    pub id: String,
    pub title: String,
    pub severity: String,
    pub description: String,
    pub protocol: Option<String>,
    pub match_expr: String,
    pub fix: Option<RuleFix>,
}

#[derive(Debug, Deserialize)]
pub struct RuleFix {
    pub steps: String,
    pub risk: String,
    pub reversible: String,
}

#[derive(Debug, Serialize)]
pub struct OtFinding {
    pub rule_id: String,
    pub title: String,
    pub severity: String,
    pub asset_ip: String,
    pub asset_port: u16,
    pub protocol: String,
    pub description: String,
    pub fix_steps: Option<String>,
}

fn load_rules(rules_dir: &str) -> Result<Vec<OtRule>> {
    let mut rules = Vec::new();
    let dir = Path::new(rules_dir);
    if !dir.is_dir() {
        anyhow::bail!("rules directory not found: {}", rules_dir);
    }
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().map(|e| e == "yml" || e == "yaml").unwrap_or(false) {
            let content = fs::read_to_string(&path)?;
            let rule: OtRule = serde_yaml::from_str(&content)?;
            rules.push(rule);
        }
    }
    Ok(rules)
}

fn evaluate_rule(rule: &OtRule, asset: &OtAsset) -> bool {
    match rule.match_expr.as_str() {
        "protocol == modbus_tcp && port == 502" => {
            matches!(asset.protocol, crate::protocols::Protocol::ModbusTcp) && asset.port == 502
        }
        "protocol == dnp3 && port == 20000" => {
            matches!(asset.protocol, crate::protocols::Protocol::Dnp3) && asset.port == 20000
        }
        "protocol == s7comm && port == 102" => {
            matches!(asset.protocol, crate::protocols::Protocol::S7comm) && asset.port == 102
        }
        "protocol == opcua && vendor == none" => {
            matches!(asset.protocol, crate::protocols::Protocol::OpcUa) && asset.vendor.is_none()
        }
        expr if expr.starts_with("port in ") => {
            let ports_str = expr.trim_start_matches("port in [").trim_end_matches(']');
            ports_str
                .split(',')
                .filter_map(|s| s.trim().parse::<u16>().ok())
                .any(|p| p == asset.port)
        }
        _ => false,
    }
}

pub async fn audit(file: &str, rules_dir: &str, format: Format) -> Result<()> {
    let content = if file == "-" {
        use std::io::Read;
        let mut buf = String::new();
        std::io::stdin().read_to_string(&mut buf)?;
        buf
    } else {
        fs::read_to_string(file)?
    };

    let assets: Vec<OtAsset> = serde_json::from_str(&content)?;
    let rules = load_rules(rules_dir)?;

    info!(assets = assets.len(), rules = rules.len(), "evaluating posture");

    let mut findings: Vec<OtFinding> = Vec::new();

    for asset in &assets {
        for rule in &rules {
            if evaluate_rule(rule, asset) {
                findings.push(OtFinding {
                    rule_id: rule.id.clone(),
                    title: rule.title.clone(),
                    severity: rule.severity.clone(),
                    asset_ip: asset.ip.clone(),
                    asset_port: asset.port,
                    protocol: format!("{:?}", asset.protocol),
                    description: rule.description.clone(),
                    fix_steps: rule.fix.as_ref().map(|f| f.steps.clone()),
                });
            }
        }
    }

    info!(findings = findings.len(), "audit complete");

    let output = match format {
        Format::Json => serde_json::to_string_pretty(&findings)?,
        Format::Text => {
            let mut out = String::new();
            out.push_str(&format!("\ncyprobe audit — {} finding(s)\n", findings.len()));
            out.push_str(&"─".repeat(72));
            out.push('\n');
            for f in &findings {
                out.push_str(&format!(
                    "  [{}] {} — {}:{} ({})\n    {}\n\n",
                    f.severity, f.rule_id, f.asset_ip, f.asset_port, f.protocol, f.title
                ));
            }
            out
        }
        Format::Sarif => serde_json::to_string_pretty(&findings)?,
    };

    print!("{output}");
    Ok(())
}
