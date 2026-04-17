use anyhow::Result;
use clap::{Parser, Subcommand};

mod active;
mod auth;
mod output;
mod passive;
mod protocols;
mod rules;

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

    /// List available network interfaces
    Interfaces,
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

        Command::Interfaces => {
            passive::list_interfaces();
            Ok(())
        }
    }
}
