use clap::{Args, Parser, Subcommand};
use totpvault_lib::SystemInfoMsg;
use totpvault_lib::totpvault_dev::TotpvaultDev;
use colored::Colorize;
use env_logger::Builder;
use zeroize::Zeroize;

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

fn get_device(cli: &Cli) -> Result<String, ()> {
    if let Some(device) = cli.device.clone() {
        return Ok(device);
    } else {
        if let Ok(device) = TotpvaultDev::find_device() {
            return Ok(device);
        } else {
            return Err(());
        }
    }
}

fn dump_device_status(device_status: &SystemInfoMsg) {
    let locked_msg = match device_status.vault_unlocked {
        true => "Unlocked".green(),
        false => "Locked".bold().red(),
    };

    let timestamp_msg = match TotpvaultDev::timesync_check(device_status.current_timestamp) {
        true => format!("{} {}", device_status.current_timestamp, "(In-sync)".green()),
        false => format!("{} {}", device_status.current_timestamp, "(Out-of-Sync)".red().bold()),
    };

    println!("Device Status:\n\tVault: {}\n\tTotal Slots: {}\n\tUsed Slots: {}\n\tFree Slots: {}\n\tCurrent Timestamp: {}\n\tVersion: {}\n\tPublic Key: {}", locked_msg, device_status.total_slots, device_status.used_slots,
    device_status.free_slots, timestamp_msg, device_status.version_str, device_status.public_key);
}
fn main() {
    let cli = Cli::parse();

    if cli.verbose {
        // Set debug! level printing
        Builder::new()
            .filter_level(log::LevelFilter::Debug)  // Set the log level to Info
            .init();
    }
    else {
        env_logger::init();
    }

    if get_device(&cli).is_err() {
        eprintln!("No TOTPVault device found!");
        return;
    }

    let d = get_device(&cli).unwrap();
    let device = d.as_str();

    match cli.command {
        Commands::SyncTime => {
            match TotpvaultDev::sync_time(device) {
                Ok(_) => println!("Successfully synced time"),
                Err(error) => eprintln!("Error syncing device time\n\tError = {}", error),
            }
        }
        Commands::ListCredentials => println!("Listing credentials..."),
        Commands::DeleteCredential(args) => println!("Deleting credential for domain: {}", args.domain_name),
        Commands::AddCredential(args) => println!("Adding credential for domain: {}", args.domain_name),
        Commands::TotpCode(args) => println!("Generating TOTP code for domain: {}", args.domain_name),
        Commands::InitVault => println!("Initializing vault..."),
        Commands::ResetVault => println!("Resetting vault..."),
        Commands::DevInfo => {
            match TotpvaultDev::get_device_status(device) {
                Ok(device_status) => {
                    dump_device_status(&device_status);
                },
                Err(error) => eprintln!("Unable to get device status from: {}\n\tError = {}", device, error),
            }
        }
        Commands::AttestDev => println!("Attesting device..."),
        Commands::ListDevices => {
            if let Ok(dev) = TotpvaultDev::find_device() {
                println!("Found TOTPVault device: {}", dev);
            } else {
                eprintln!("No TOTPVault device found!");
            }
        }
        Commands::UnlockVault => {
            let mut password = rpassword::prompt_password("Enter password: ").unwrap();

            match TotpvaultDev::unlock_vault(device, &password) {
                Ok(_) => println!("Successfully unlocked vault"),
                Err(error) => eprintln!("Error unlocking vault\n\tError = {}", error),
            }
            password.zeroize();
        }
        Commands::LockVault => println!("Locking vault..."),
        Commands::DumpLogs => println!("Dumping logs..."),
    }
}
