use anyhow::Result;
use clap::{Parser, Subcommand};

mod active;
mod auth;
mod discover;
mod netscan;
mod output;
mod passive;
mod protocols;
mod rules;
mod self_update;

#[derive(Parser)]
#[command(name = "cyprobe", version, about = "OT/SCADA network discovery and posture probe")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Passive network capture — sniff traffic and fingerprint OT devices
    Passive {
        /// Network interface to capture on
        #[arg(short, long)]
        interface: String,

        /// Duration in seconds (0 = indefinite)
        #[arg(short, long, default_value = "300")]
        duration: u64,

        /// Output format
        #[arg(short, long, default_value = "json")]
        format: output::Format,

        /// Output file (default: stdout)
        #[arg(short = 'o', long)]
        output: Option<String>,
    },

    /// Active probe — read-only queries to discover device identity and firmware
    Active {
        /// Target CIDR or IP (e.g. 10.0.1.0/24)
        #[arg(short, long)]
        targets: String,

        /// Protocols to probe (comma-separated: modbus,s7,opcua,bacnet,enip,iec104)
        #[arg(short, long, default_value = "modbus,s7,opcua")]
        protocols: String,

        /// Max probes per second per target
        #[arg(long, default_value = "1")]
        rate_limit: u32,

        /// Skip the safety confirmation prompt
        #[arg(long)]
        active_confirm: bool,

        /// Output format
        #[arg(short, long, default_value = "json")]
        format: output::Format,

        /// Output file (default: stdout)
        #[arg(short = 'o', long)]
        output: Option<String>,
    },

    /// Upload discovered assets to the Cybrium platform
    Upload {
        /// Path to cyprobe JSON output file
        #[arg(short, long)]
        file: String,

        /// Platform URL
        #[arg(long, default_value = "https://app.cybrium.ai")]
        platform: String,

        /// API key or agent token
        #[arg(long, env = "CYPROBE_TOKEN")]
        token: String,
    },

    /// Evaluate OT posture rules against discovered assets
    Audit {
        /// Path to cyprobe JSON output (or - for stdin)
        #[arg(short, long)]
        file: String,

        /// Rules directory
        #[arg(short, long, default_value = "rules/ot")]
        rules: String,

        /// Output format
        #[arg(short = 'F', long, default_value = "text")]
        format: output::Format,
    },

    /// Network service scan — TCP template engine (Redis, MongoDB, FTP, SSH, etc.)
    Netscan {
        /// Target CIDR or IP (e.g. 10.0.1.0/24 or 192.168.1.1)
        #[arg(short, long)]
        targets: String,

        /// Ports to scan (comma-separated, ranges with dash). Default: common service ports
        #[arg(short, long)]
        ports: Option<String>,

        /// Custom templates directory (YAML files)
        #[arg(long)]
        templates: Option<String>,

        /// Max probes per second
        #[arg(long, default_value = "50")]
        rate_limit: u32,

        /// Connection timeout in milliseconds
        #[arg(long, default_value = "3000")]
        timeout: u64,

        /// Output format
        #[arg(short, long, default_value = "json")]
        format: output::Format,

        /// Output file (default: stdout)
        #[arg(short = 'o', long)]
        output: Option<String>,
    },

    /// Discover all devices on a network — ARP scan + MAC vendor lookup + NetBIOS
    Discover {
        /// Network interface to scan on
        #[arg(short, long)]
        interface: String,

        /// Target CIDR (e.g. 10.0.1.0/24)
        #[arg(short, long)]
        targets: String,

        /// ARP response timeout in milliseconds
        #[arg(long, default_value = "3000")]
        timeout: u64,

        /// Disable NetBIOS name resolution
        #[arg(long)]
        no_netbios: bool,

        /// Output format
        #[arg(short, long, default_value = "json")]
        format: output::Format,

        /// Output file (default: stdout)
        #[arg(short = 'o', long)]
        output: Option<String>,
    },

    /// List available network interfaces
    Interfaces,

    /// Check for updates and self-update the binary
    Update,

    /// Show version and check for updates
    Version,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "cyprobe=info".into()),
        )
        .init();

    let cli = Cli::parse();

    // Print banner for scan commands
    match &cli.command {
        Command::Passive { .. } | Command::Active { .. } | Command::Audit { .. } | Command::Netscan { .. } | Command::Discover { .. } => {
            eprintln!("\x1b[35m");
            eprintln!(r#"   ___  _   _  ___  ___  ___  ___  ___ "#);
            eprintln!(r#"  / __|| | | || _ \| _ \/ _ \| _ )| __|"#);
            eprintln!(r#" | (__ | |_| ||  _/|   / (_) || _ \| _| "#);
            eprintln!(r#"  \___| \__, ||_|  |_|_\\___/ |___/|___|"#);
            eprintln!(r#"        |___/                            "#);
            eprintln!("\x1b[0m");
            eprintln!(
                "  \x1b[35m\x1b[1mcyprobe\x1b[0m v{} — \x1b[2mCybrium AI OT/SCADA Scanner\x1b[0m",
                env!("CARGO_PKG_VERSION")
            );
            eprintln!();
        }
        _ => {}
    }

    match cli.command {
        Command::Passive {
            interface,
            duration,
            format,
            output: out,
        } => passive::run(&interface, duration, format, out.as_deref()).await,

        Command::Active {
            targets,
            protocols,
            rate_limit,
            active_confirm,
            format,
            output: out,
        } => {
            if !active_confirm {
                eprintln!("WARNING: Active probing sends read-only queries to OT devices.");
                eprintln!("OT devices are safety-critical — a crashed PLC can halt a factory.");
                eprintln!();
                eprintln!("Re-run with --active-confirm to proceed.");
                std::process::exit(1);
            }
            active::run(&targets, &protocols, rate_limit, format, out.as_deref()).await
        }

        Command::Upload {
            file,
            platform,
            token,
        } => output::upload(&file, &platform, &token).await,

        Command::Audit {
            file,
            rules: rules_dir,
            format,
        } => rules::audit(&file, &rules_dir, format).await,

        Command::Netscan {
            targets,
            ports,
            templates,
            rate_limit,
            timeout: timeout_ms,
            format,
            output: out,
        } => netscan::run(
            &targets,
            ports.as_deref(),
            templates.as_deref(),
            rate_limit,
            timeout_ms,
            format,
            out.as_deref(),
        ).await,

        Command::Discover {
            interface,
            targets,
            timeout,
            no_netbios,
            format,
            output: out,
        } => discover::run(
            &interface, &targets, timeout, !no_netbios, format, out.as_deref(),
        ).await,

        Command::Interfaces => {
            passive::list_interfaces();
            Ok(())
        }

        Command::Update => {
            self_update::update("cybrium-ai/cyprobe", "cyprobe").await
        }

        Command::Version => {
            self_update::version("cybrium-ai/cyprobe").await;
            Ok(())
        }
    }
}
