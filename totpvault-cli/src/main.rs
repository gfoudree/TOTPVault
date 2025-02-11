use clap::{Args, Parser, Subcommand};
use totpvault_lib::totpvault_dev::TotpvaultDev;

#[derive(Parser)]
#[command(name = "TOTPVault CLI")]
#[command(about = "CLI tool to manage TOTPVault", version = "1.0.0")]
struct Cli {
    #[arg(short, long, global = true, required = false, help = "Verbose mode")]
    verbose: bool,
    #[arg(short, long, global = true, required = false, help = "Path to specific device. Ex: /dev/ttyACM0")]
    device: Option<String>,
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    #[command(about = "Synchronize the system time")]
    SyncTime,

    #[command(about = "List all stored credentials")]
    ListCredentials,

    #[command(about = "Delete a credential for a specific domain")]
    DeleteCredential(DomainArgs),

    #[command(about = "Add a new TOTP credential")]
    AddCredential(DomainArgs),

    #[command(about = "Get TOTP credential for a domain")]
    TotpCode(DomainArgs),

    #[command(about = "Initialize the vault")]
    InitVault,

    #[command(about = "Reset the vault")]
    ResetVault,

    #[command(about = "Get device information")]
    DevInfo,

    #[command(about = "Perform device attestation")]
    AttestDev,

    #[command(about = "List connected devices")]
    ListDevices,

    #[command(about = "Unlock the vault")]
    UnlockVault,

    #[command(about = "Lock the vault")]
    LockVault,

    #[command(about = "Dump system logs")]
    DumpLogs,
}

#[derive(Args)]
struct DomainArgs {
    #[arg(long)]
    domain_name: String,
}

fn main() {
    let cli = Cli::parse();

    if cli.verbose {
        // Set debug! level printing
    }

    match cli.command {
        Commands::SyncTime => println!("Syncing time..."),
        Commands::ListCredentials => println!("Listing credentials..."),
        Commands::DeleteCredential(args) => println!("Deleting credential for domain: {}", args.domain_name),
        Commands::AddCredential(args) => println!("Adding credential for domain: {}", args.domain_name),
        Commands::TotpCode(args) => println!("Generating TOTP code for domain: {}", args.domain_name),
        Commands::InitVault => println!("Initializing vault..."),
        Commands::ResetVault => println!("Resetting vault..."),
        Commands::DevInfo => println!("Fetching device info..."),
        Commands::AttestDev => println!("Attesting device..."),
        Commands::ListDevices => {
            if let Ok(dev) = TotpvaultDev::find_device() {
                println!("Found TOTPVault device: {}", dev);
            } else {
                println!("No TOTPVault device found!");
            }
        }
        Commands::UnlockVault => println!("Unlocking vault..."),
        Commands::LockVault => println!("Locking vault..."),
        Commands::DumpLogs => println!("Dumping logs..."),
    }
}
