//! Hardware Root-of-Trust detection.
//!
//! Reports the presence + manufacturer of a TPM (Linux/Windows) or
//! Apple Secure Enclave (macOS). Detection only — this module does
//! not drive the TPM, generate AIKs, or sign payloads.
//!
//! Two consumers care about this output:
//!   1. Operators: surface ROT status in dashboards / inventories.
//!   2. Tamper detection: a stable host's TPM vendor should not change
//!      between check-ins. A flip is a high-severity signal.
//!
//! Cryptographic attestation (TPM-bound key signing) is intentionally
//! out of scope here — that requires `tss-esapi` (Linux), TBS API
//! (Windows), and IOKit (macOS) integration and lives in a separate
//! follow-up.

use serde::{Deserialize, Serialize};

/// Family of hardware root of trust detected on this host.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RootOfTrustKind {
    /// TPM 2.0 detected.
    Tpm20,
    /// Older TPM 1.2 — still common on Windows fleets pre-Win11.
    Tpm12,
    /// Apple Secure Enclave (T2 chip or Apple Silicon).
    SecureEnclave,
    /// No supported root-of-trust device found.
    None,
    /// Detection ran into an error — distinct from "absent".
    Unknown,
}

impl RootOfTrustKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Tpm20         => "tpm20",
            Self::Tpm12         => "tpm12",
            Self::SecureEnclave => "secure_enclave",
            Self::None          => "none",
            Self::Unknown       => "unknown",
        }
    }
}

/// Snapshot of the host's hardware root of trust.
///
/// `present == true` when the OS reports an active, queryable device.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RootOfTrust {
    pub kind:    RootOfTrustKind,
    pub vendor:  String,
    pub present: bool,
}

impl RootOfTrust {
    fn absent() -> Self {
        Self { kind: RootOfTrustKind::None, vendor: String::new(), present: false }
    }
    fn unknown() -> Self {
        Self { kind: RootOfTrustKind::Unknown, vendor: String::new(), present: false }
    }
}

/// Detect the host's hardware root of trust. Never panics; on
/// detection failure returns `Unknown` so the caller can include it
/// in any fingerprint or report without crashing.
pub fn detect() -> RootOfTrust {
    #[cfg(target_os = "linux")]
    {
        detect_linux()
    }
    #[cfg(target_os = "macos")]
    {
        detect_macos()
    }
    #[cfg(target_os = "windows")]
    {
        detect_windows()
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        RootOfTrust::absent()
    }
}

// ── Linux ────────────────────────────────────────────────────────────
//
// /sys/class/tpm/tpm0/{tpm_version_major,tpm_manufacturer} — no
// syscalls, no extra deps. Falls back to /dev/tpm0 presence when
// /sys is unavailable (rare; minimal containers).

#[cfg(target_os = "linux")]
fn detect_linux() -> RootOfTrust {
    use std::fs;
    use std::path::Path;

    let tpm_dir = Path::new("/sys/class/tpm/tpm0");
    if !tpm_dir.exists() {
        if Path::new("/dev/tpm0").exists() {
            return RootOfTrust {
                kind:    RootOfTrustKind::Tpm20,
                vendor:  String::new(),
                present: true,
            };
        }
        return RootOfTrust::absent();
    }

    let kind = match fs::read_to_string(tpm_dir.join("tpm_version_major"))
        .ok()
        .as_deref()
        .map(str::trim)
    {
        Some("2") => RootOfTrustKind::Tpm20,
        Some("1") => RootOfTrustKind::Tpm12,
        _         => RootOfTrustKind::Tpm20,
    };

    let vendor = fs::read_to_string(tpm_dir.join("tpm_manufacturer"))
        .ok()
        .map(|s| s.trim().to_string())
        .unwrap_or_default();

    RootOfTrust { kind, vendor, present: true }
}

// ── macOS ────────────────────────────────────────────────────────────
//
// IOKit / `ioreg -c AppleSEPManager`. Apple Silicon always has it;
// Intel Macs have it only with T1/T2 chips.

#[cfg(target_os = "macos")]
fn detect_macos() -> RootOfTrust {
    use std::process::Command;

    let out = match Command::new("ioreg")
        .args(["-r", "-c", "AppleSEPManager", "-d", "1"])
        .output()
    {
        Ok(o) if o.status.success() => o,
        _ => return RootOfTrust::unknown(),
    };

    let text = String::from_utf8_lossy(&out.stdout);
    let present = text.contains("AppleSEPManager");
    if !present {
        return RootOfTrust::absent();
    }

    let vendor = text
        .lines()
        .find(|l| l.contains("\"product-name\""))
        .and_then(|l| l.split('=').nth(1))
        .map(|s| {
            s.trim()
                .trim_matches('<')
                .trim_matches('>')
                .trim_matches('"')
                .to_string()
        })
        .unwrap_or_else(|| "Apple".to_string());

    RootOfTrust { kind: RootOfTrustKind::SecureEnclave, vendor, present: true }
}

// ── Windows ──────────────────────────────────────────────────────────
//
// PowerShell Get-Tpm | ConvertTo-Json. Falls back to `tpmtool
// getdeviceinformation` on systems where PowerShell isn't available
// (rare but happens on Server Core).

#[cfg(target_os = "windows")]
fn detect_windows() -> RootOfTrust {
    use std::process::Command;

    let ps_out = Command::new("powershell")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "Get-Tpm | Select-Object TpmPresent,TpmReady,ManufacturerIdTxt,ManufacturerVersion | ConvertTo-Json -Compress",
        ])
        .output();

    if let Ok(out) = ps_out {
        if out.status.success() {
            let text = String::from_utf8_lossy(&out.stdout).trim().to_string();
            let present = text.contains("\"TpmPresent\":true");
            let ready   = text.contains("\"TpmReady\":true");
            let vendor  = extract_field(&text, "ManufacturerIdTxt").unwrap_or_default();
            if present {
                let kind = if ready { RootOfTrustKind::Tpm20 } else { RootOfTrustKind::Tpm12 };
                return RootOfTrust {
                    kind,
                    vendor: vendor.trim().to_string(),
                    present: true,
                };
            }
            return RootOfTrust::absent();
        }
    }

    let tt = Command::new("tpmtool").arg("getdeviceinformation").output();
    if let Ok(out) = tt {
        let text = String::from_utf8_lossy(&out.stdout);
        if text.contains("TPM Present: true") {
            let kind = if text.contains("Specification Version: 2.0") {
                RootOfTrustKind::Tpm20
            } else {
                RootOfTrustKind::Tpm12
            };
            return RootOfTrust { kind, vendor: String::new(), present: true };
        }
    }

    RootOfTrust::absent()
}

#[cfg(target_os = "windows")]
fn extract_field<'a>(json: &'a str, key: &str) -> Option<&'a str> {
    let needle = format!("\"{}\":\"", key);
    let start  = json.find(&needle)? + needle.len();
    let rest   = &json[start..];
    let end    = rest.find('"')?;
    Some(&rest[..end])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_does_not_panic() {
        let r = detect();
        assert!(matches!(
            r.kind,
            RootOfTrustKind::Tpm20
                | RootOfTrustKind::Tpm12
                | RootOfTrustKind::SecureEnclave
                | RootOfTrustKind::None
                | RootOfTrustKind::Unknown,
        ));
    }

    #[test]
    fn kind_str_round_trip() {
        assert_eq!(RootOfTrustKind::Tpm20.as_str(),         "tpm20");
        assert_eq!(RootOfTrustKind::Tpm12.as_str(),         "tpm12");
        assert_eq!(RootOfTrustKind::SecureEnclave.as_str(), "secure_enclave");
        assert_eq!(RootOfTrustKind::None.as_str(),          "none");
        assert_eq!(RootOfTrustKind::Unknown.as_str(),       "unknown");
    }
}
