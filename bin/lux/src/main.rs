//! Lux CLI - Command-line interface for Lux distributed filesystem.
//!
//! Provides commands for:
//! - Mounting Lux URIs as local filesystems
//! - Creating and managing mutable objects
//! - Storing and retrieving blobs
//! - Network status and diagnostics

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use tracing::{info, Level};
use tracing_subscriber::FmtSubscriber;

/// Lux distributed filesystem CLI.
#[derive(Parser)]
#[command(name = "lux")]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// Verbosity level (-v, -vv, -vvv)
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,

    /// Configuration file path
    #[arg(short, long, default_value = "~/.lux/config.toml")]
    config: PathBuf,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Mount a Lux URI as a local filesystem
    Mount {
        /// Lux URI to mount (lux:obj:... or lux:blob:...)
        uri: String,

        /// Mount point path
        mount_point: PathBuf,

        /// Mount read-only
        #[arg(long)]
        read_only: bool,

        /// Run in foreground
        #[arg(long)]
        foreground: bool,
    },

    /// Unmount a Lux filesystem
    Unmount {
        /// Mount point path
        mount_point: PathBuf,
    },

    /// Create a new mutable object
    Create {
        /// Initial file to upload (optional)
        #[arg(short, long)]
        file: Option<PathBuf>,

        /// Output file for the URI
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// Store a blob in the network
    Put {
        /// File to store
        file: PathBuf,

        /// Output file for the URI
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// Retrieve a blob from the network
    Get {
        /// Lux URI to retrieve
        uri: String,

        /// Output file (default: stdout)
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// Show information about a URI
    Info {
        /// Lux URI to inspect
        uri: String,
    },

    /// List revisions of a mutable object
    Revisions {
        /// Object URI
        uri: String,

        /// Number of revisions to show
        #[arg(short, long, default_value = "10")]
        limit: usize,
    },

    /// Network status and diagnostics
    Status {
        /// Show detailed information
        #[arg(long)]
        detailed: bool,
    },

    /// Initialize Lux configuration
    Init {
        /// Force overwrite existing config
        #[arg(long)]
        force: bool,
    },

    /// Generate a new identity
    Keygen {
        /// Output file for the keypair
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    // Setup logging
    let level = match cli.verbose {
        0 => Level::WARN,
        1 => Level::INFO,
        2 => Level::DEBUG,
        _ => Level::TRACE,
    };

    let subscriber = FmtSubscriber::builder().with_max_level(level).finish();
    tracing::subscriber::set_global_default(subscriber).context("Failed to set up logging")?;

    match cli.command {
        Commands::Mount {
            uri,
            mount_point,
            read_only,
            foreground,
        } => cmd_mount(&uri, &mount_point, read_only, foreground),

        Commands::Unmount { mount_point } => cmd_unmount(&mount_point),

        Commands::Create { file, output } => cmd_create(file.as_deref(), output.as_deref()),

        Commands::Put { file, output } => cmd_put(&file, output.as_deref()),

        Commands::Get { uri, output } => cmd_get(&uri, output.as_deref()),

        Commands::Info { uri } => cmd_info(&uri),

        Commands::Revisions { uri, limit } => cmd_revisions(&uri, limit),

        Commands::Status { detailed } => cmd_status(detailed),

        Commands::Init { force } => cmd_init(force),

        Commands::Keygen { output } => cmd_keygen(output.as_deref()),
    }
}

fn cmd_mount(uri: &str, mount_point: &PathBuf, read_only: bool, foreground: bool) -> Result<()> {
    use lux_proto::uri::LuxUri;

    info!("Mounting {} at {:?}", uri, mount_point);

    let _parsed_uri = uri.parse::<LuxUri>().context("Invalid Lux URI")?;

    // Ensure mount point exists
    std::fs::create_dir_all(mount_point).context("Failed to create mount point")?;

    println!("Mount would occur here (FUSE not fully implemented in demo)");
    println!("URI: {}", uri);
    println!("Mount point: {:?}", mount_point);
    println!("Read-only: {}", read_only);
    println!("Foreground: {}", foreground);

    Ok(())
}

fn cmd_unmount(mount_point: &PathBuf) -> Result<()> {
    info!("Unmounting {:?}", mount_point);
    println!("Unmount would occur here");
    Ok(())
}

fn cmd_create(file: Option<&std::path::Path>, output: Option<&std::path::Path>) -> Result<()> {
    use lux_core::{CapabilitySecret, ObjectId};
    use lux_proto::uri::ObjectUri;

    info!("Creating new mutable object");

    let object_id = ObjectId::random();
    let capability = CapabilitySecret::random();
    let uri = ObjectUri::new(object_id, capability);

    let uri_string = uri.to_string();

    if let Some(output_path) = output {
        std::fs::write(output_path, &uri_string).context("Failed to write URI to file")?;
        println!("URI written to {:?}", output_path);
    } else {
        println!("{}", uri_string);
    }

    if let Some(file_path) = file {
        println!("Would upload {:?} as initial content", file_path);
    }

    Ok(())
}

fn cmd_put(file: &PathBuf, output: Option<&std::path::Path>) -> Result<()> {
    use lux_core::BlobId;
    use lux_proto::uri::BlobUri;

    info!("Storing blob from {:?}", file);

    let data = std::fs::read(file).context("Failed to read file")?;
    let blob_id = BlobId::from_plaintext(&data);
    let uri = BlobUri::new(blob_id);

    let uri_string = uri.to_string();

    if let Some(output_path) = output {
        std::fs::write(output_path, &uri_string).context("Failed to write URI to file")?;
        println!("URI written to {:?}", output_path);
    } else {
        println!("{}", uri_string);
    }

    println!(
        "Blob ID: {} ({} bytes)",
        blob_id.to_hex(),
        data.len()
    );

    Ok(())
}

fn cmd_get(uri: &str, output: Option<&std::path::Path>) -> Result<()> {
    use lux_proto::uri::LuxUri;

    info!("Retrieving {}", uri);

    let parsed_uri = uri.parse::<LuxUri>().context("Invalid Lux URI")?;

    match parsed_uri {
        LuxUri::Blob(blob_uri) => {
            println!("Would retrieve blob: {}", blob_uri.blob_id.to_hex());
        }
        LuxUri::Object(obj_uri) => {
            println!("Would retrieve object: {}", obj_uri.object_id.to_hex());
            if let Some(rev) = obj_uri.revision {
                println!("At revision: {}", rev);
            }
        }
    }

    if let Some(output_path) = output {
        println!("Would write to {:?}", output_path);
    }

    Ok(())
}

fn cmd_info(uri: &str) -> Result<()> {
    use lux_proto::uri::LuxUri;

    let parsed_uri = uri.parse::<LuxUri>().context("Invalid Lux URI")?;

    match parsed_uri {
        LuxUri::Blob(blob_uri) => {
            println!("Type: Blob (immutable)");
            println!("Blob ID: {}", blob_uri.blob_id.to_hex());
        }
        LuxUri::Object(obj_uri) => {
            println!("Type: Object (mutable)");
            println!("Object ID: {}", obj_uri.object_id.to_hex());
            println!(
                "Capability: {}",
                base64::Engine::encode(
                    &base64::engine::general_purpose::URL_SAFE_NO_PAD,
                    obj_uri.capability_secret.0
                )
            );
            if let Some(rev) = obj_uri.revision {
                println!("Pinned revision: {}", rev);
            }
        }
    }

    Ok(())
}

fn cmd_revisions(uri: &str, limit: usize) -> Result<()> {
    use lux_proto::uri::LuxUri;

    let parsed_uri = uri.parse::<LuxUri>().context("Invalid Lux URI")?;

    match parsed_uri {
        LuxUri::Object(obj_uri) => {
            println!("Object: {}", obj_uri.object_id.to_hex());
            println!("Revisions (would query network):");
            println!("  (revision listing not implemented in demo)");
        }
        LuxUri::Blob(_) => {
            anyhow::bail!("Blobs are immutable and don't have revisions");
        }
    }

    Ok(())
}

fn cmd_status(detailed: bool) -> Result<()> {
    println!("Lux Network Status");
    println!("==================");
    println!();
    println!("Node ID: (would show local node ID)");
    println!("Connected peers: 0");
    println!("DHT records: 0");
    println!("Stored chunks: 0");

    if detailed {
        println!();
        println!("Detailed Statistics:");
        println!("  Routing table buckets: 256");
        println!("  Active connections: 0");
        println!("  Bandwidth: 0 B/s in, 0 B/s out");
    }

    Ok(())
}

fn cmd_init(force: bool) -> Result<()> {
    let config_dir = dirs::home_dir()
        .context("Could not find home directory")?
        .join(".lux");

    if config_dir.exists() && !force {
        anyhow::bail!("Configuration already exists at {:?}. Use --force to overwrite.", config_dir);
    }

    std::fs::create_dir_all(&config_dir).context("Failed to create config directory")?;

    let config_content = r#"# Lux Configuration

[node]
# Node identity (auto-generated on first run)
# identity_file = "~/.lux/identity.key"

[network]
# Listen address
listen = "0.0.0.0:4242"
# Bootstrap nodes
# bootstrap = ["node1.example.com:4242", "node2.example.com:4242"]

[storage]
# Data directory
data_dir = "~/.lux/data"
# Maximum cache size in GB
max_cache_gb = 10

[resilience]
# Default replication factor
min_replicas = 3
# Lease renewal period in days
lease_ttl_days = 7
"#;

    let config_file = config_dir.join("config.toml");
    std::fs::write(&config_file, config_content).context("Failed to write config file")?;

    println!("Initialized Lux configuration at {:?}", config_dir);

    // Generate identity
    cmd_keygen(Some(&config_dir.join("identity.key")))?;

    Ok(())
}

fn cmd_keygen(output: Option<&std::path::Path>) -> Result<()> {
    use lux_core::{NodeId, SigningKey};

    let signing_key = SigningKey::random();
    let public_key = signing_key.public_key();
    let node_id = NodeId::from_public_key(&public_key);

    println!("Generated new identity:");
    println!("  Node ID: {}", node_id.to_hex());
    println!("  Public key: {}", hex::encode(public_key));

    if let Some(output_path) = output {
        let key_data = format!(
            "# Lux Identity Key\n# Node ID: {}\nprivate: {}\npublic: {}\n",
            node_id.to_hex(),
            hex::encode(signing_key.as_bytes()),
            hex::encode(public_key)
        );
        std::fs::write(output_path, key_data).context("Failed to write key file")?;
        println!("  Key saved to {:?}", output_path);
    }

    Ok(())
}
