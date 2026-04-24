//! Self-update — download latest release from GitHub and replace the binary.

use anyhow::{bail, Result};

pub async fn version(repo: &str) {
    let current = env!("CARGO_PKG_VERSION");
    println!("{} {} — Cybrium AI", env!("CARGO_PKG_NAME"), current);
    println!("https://github.com/{repo}");

    let client = reqwest::Client::builder()
        .user_agent(format!("{}/{current}", env!("CARGO_PKG_NAME")))
        .timeout(std::time::Duration::from_secs(3))
        .build()
        .unwrap();

    if let Ok(resp) = client
        .get(format!("https://api.github.com/repos/{repo}/releases/latest"))
        .header("Accept", "application/vnd.github+json")
        .send()
        .await
    {
        if let Ok(data) = resp.json::<serde_json::Value>().await {
            let latest = data["tag_name"]
                .as_str()
                .unwrap_or("")
                .trim_start_matches('v');
            if !latest.is_empty() && latest != current {
                println!(
                    "\nUpdate available: v{} (run: {} update)",
                    latest,
                    env!("CARGO_PKG_NAME")
                );
            }
        }
    }
}

pub async fn update(repo: &str, binary_name: &str) -> Result<()> {
    let current = env!("CARGO_PKG_VERSION");
    eprintln!("Current version: {current}");
    eprintln!("Checking for updates...");

    let client = reqwest::Client::builder()
        .user_agent(format!("{binary_name}/{current}"))
        .build()?;

    let resp = client
        .get(format!("https://api.github.com/repos/{repo}/releases/latest"))
        .header("Accept", "application/vnd.github+json")
        .send()
        .await?;

    if !resp.status().is_success() {
        bail!("Cannot reach GitHub API");
    }

    let data: serde_json::Value = resp.json().await?;
    let latest = data["tag_name"]
        .as_str()
        .unwrap_or("unknown")
        .trim_start_matches('v');

    if latest == current {
        eprintln!("Already up to date!");
        return Ok(());
    }

    eprintln!("New version: {current} -> {latest}");

    // Determine platform asset name
    let asset_name = if cfg!(target_os = "macos") && cfg!(target_arch = "aarch64") {
        format!("{binary_name}-darwin-arm64")
    } else if cfg!(target_os = "macos") && cfg!(target_arch = "x86_64") {
        format!("{binary_name}-darwin-amd64")
    } else if cfg!(target_os = "linux") && cfg!(target_arch = "aarch64") {
        format!("{binary_name}-linux-arm64")
    } else {
        format!("{binary_name}-linux-amd64")
    };

    let download_url = data["assets"]
        .as_array()
        .and_then(|a| {
            a.iter()
                .find(|asset| asset["name"].as_str().map_or(false, |n| n == asset_name))
                .and_then(|asset| asset["browser_download_url"].as_str())
        });

    let url = match download_url {
        Some(u) => u,
        None => bail!("No binary found for platform: {asset_name}"),
    };

    eprintln!("Downloading {asset_name}...");
    let resp = client.get(url).send().await?;
    let bytes = resp.bytes().await?;

    if bytes.is_empty() {
        bail!("Download returned empty");
    }

    let exe_path = std::env::current_exe()?;
    let backup = exe_path.with_extension("old");

    std::fs::rename(&exe_path, &backup)?;

    if let Err(e) = std::fs::write(&exe_path, &bytes) {
        std::fs::rename(&backup, &exe_path).ok();
        bail!("Cannot write new binary: {e}");
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&exe_path, std::fs::Permissions::from_mode(0o755)).ok();
    }

    std::fs::remove_file(&backup).ok();
    eprintln!("Updated to v{latest}!");
    Ok(())
}
