use clap::{Args, Parser, Subcommand};
use totpvault_lib::SystemInfoMsg;
use colored::Colorize;
use env_logger::Builder;
use zeroize::Zeroize;
use crate::totpvault_dev::TotpvaultDev;

mod totpvault_dev;
mod totpvault_comm;

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

    #[command(about = "Initialize/Reset the vault (danger)")]
    InitVault,

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
        Commands::ListCredentials => {
            match TotpvaultDev::list_stored_credentials(device) {
                Ok(credentials) => {
                    println!("{:?}", credentials);
                }
                Err(error) => eprintln!("Error listing stored credentials. {}", error),
            }
        }
        Commands::DeleteCredential(args) => todo!("Deleting credential for domain: {}", args.domain_name),
        Commands::AddCredential(args) => {
            let mut totp_secret = rpassword::prompt_password("Enter TOTP Secret Key: ").unwrap();
            match TotpvaultDev::add_credential(device, args.domain_name.as_str(), totp_secret.as_str()) {
                Ok(_) => println!("Successfully added credential"),
                Err(error) => eprintln!("{}", error),
            }
            totp_secret.zeroize();
        }
        Commands::TotpCode(args) => {
            match TotpvaultDev::get_totp_code(device, args.domain_name.as_str()) {
                Ok(totp_code) => {
                    let time_remaining = TotpvaultDev::get_remaining_totp_ticks();
                    println!("{}\t{}s remaining", totp_code, time_remaining);
                }
            Err(error) => eprintln!("Error getting TOTP code for {}: {}", args.domain_name, error),
            }
        }
        Commands::InitVault => {
            println!("{}", "**************** WARNING ****************".bold().red());
            println!("Initializing the vault will {}!\nPlease make sure you will not be locked out of your accounts!\n\nDo you want to continue? (yes/no):", "WIPE EXISTING CREDENTIALS".bold().red());
            let mut response = String::new();
            std::io::stdin().read_line(&mut response).unwrap();
            if response.to_lowercase().trim() == "yes" {
                let mut p1 = rpassword::prompt_password("Enter vault password: ").unwrap();
                let mut p2 = rpassword::prompt_password("Enter vault password (confirm): ").unwrap();
                if p1 == p2 {
                    match TotpvaultDev::init_vault(&device, &p1) {
                        Ok(_) => println!("Successfully initialized vault!"),
                        Err(error) => eprintln!("Error initializing vault: {}", error),
                    }
                } else {
                    eprintln!("Passwords do not match!");
                }
                p1.zeroize();
                p2.zeroize();
            }
        }
        Commands::DevInfo => {
            match TotpvaultDev::get_device_status(device) {
                Ok(device_status) => {
                    dump_device_status(&device_status);
                },
                Err(error) => eprintln!("Unable to get device status from: {}\n\tError = {}", device, error),
            }
        }
        Commands::AttestDev => {
            match TotpvaultDev::get_device_status(device) {
                Ok(device_status) => {
                    let pub_key_b64 = device_status.public_key;
                        match TotpvaultDev::attest_device(device, pub_key_b64.as_str()) {
                            Ok(_) => println!("Successfully attested device"),
                            Err(error) => eprintln!("Error attesting device: {}", error),
                        }
                },
                Err(e) => eprintln!("Unable to get device status from: {}\n\tError = {}", device, e),
            }
        }
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
        Commands::LockVault => {
            match TotpvaultDev::lock_vault(device) {
                Ok(_) => println!("{}", "Locked vault".green()),
                Err(error) => eprintln!("Error locking vault: {}", error),
            }
        }
        Commands::DumpLogs => todo!("Dumping logs..."),
    }
}
