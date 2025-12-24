use std::path::absolute;
use clap::{Args, Parser, Subcommand};
use log::{warn, debug};
use totpvault_lib::SystemInfoMsg;
use colored::Colorize;
use env_logger::Builder;
use zeroize::Zeroize;
use crate::dev::TotpvaultDev;
use chrono::Utc;

mod dev;
mod comm;
mod tests;

#[derive(Parser)]
#[command(name = "totpvault-cli")]
#[command(about = "CLI tool to manage TOTPVault", version = "1.0.0")]
struct Cli {
    #[arg(short, long, global = true, required = false, help = "Verbose mode")]
    verbose: bool,
    #[arg(short = 'p', long, global = true, required = false, help = "Path to specific device. Ex: /dev/ttyACM0")]
    device: Option<String>,
    #[arg(short = 't', long, global = true, required = false, help = "Specify device communication timeout in ms")]
    timeout: Option<u64>,
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
    AttestDev(PublicKeyArgs),

    #[command(about = "List connected devices")]
    ListDevices,

    #[command(about = "Unlock the vault")]
    UnlockVault,

    #[command(about = "Lock the vault")]
    LockVault,
}

#[derive(Args)]
struct DomainArgs {
    #[arg(short = 'd', long, required = true, help = "Domain name of the TOTP code to get")]
    domain_name: String,
}

#[derive(Args)]
struct PublicKeyArgs {
    #[arg(short = 'k', long, required = false, help = "Public key of the device to attest")]
    public_key: Option<String>,
}

fn get_device(cli: &Cli) -> Result<String, ()> {
    if let Some(device) = cli.device.clone() {
        Ok(device)
    } else {
        if let Ok(device) = TotpvaultDev::find_device() {
            Ok(device)
        } else {
            Err(())
        }
    }
}

fn dump_device_status(device_status: &SystemInfoMsg) {
    let locked_msg = match device_status.vault_unlocked {
        true => "Unlocked".green(),
        false => "Locked".bold().red(),
    };

    let timestamp_msg = match TotpvaultDev::timesync_check(device_status.current_timestamp) {
        true => {
            let time_delta = (Utc::now().timestamp() as u64).abs_diff(device_status.current_timestamp);
            format!("{} delta={} {}", device_status.current_timestamp, time_delta, "(In-sync)".green())
        },
        false => {
            let time_delta = (Utc::now().timestamp() as u64).abs_diff(device_status.current_timestamp);
            format!("{} delta={} {}", device_status.current_timestamp, time_delta, "(Out-of-Sync)".red().bold())
        },
    };

    println!("Device Status:\n\tVault: {}\n\tTotal Slots: {}\n\tUsed Slots: {}\n\tFree Slots: {}\n\tCurrent Timestamp: {}\n\tVersion: {}\n\tPublic Key: {}", locked_msg, device_status.total_slots, device_status.used_slots,
    device_status.free_slots, timestamp_msg, device_status.version_str, device_status.public_key);

    if let Ok(hash) = TotpvaultDev::public_key_to_hash(&device_status.public_key) {
        println!("\tKey Fingerprint: {}", hash);
    } else {
        debug!("Corrupted public key! Key fingerprint: {}", device_status.public_key);
    }
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
            match TotpvaultDev::sync_time(device, cli.timeout) {
                Ok(utc_time) => println!("Successfully synced time to: {}", utc_time.yellow()),
                Err(error) => eprintln!("Error syncing device time\n\tError = {}", error),
            }
        }
        Commands::ListCredentials => {
            match TotpvaultDev::list_stored_credentials(device, cli.timeout) {
                Ok(credentials) => {
                    for (i, cred) in credentials.iter().enumerate() {
                        println!("[Slot {}]: {}", i, cred.domain_name.green());
                    }
                }
                Err(error) => eprintln!("Error listing stored credentials. {}", error),
            }
        }
        Commands::DeleteCredential(args) => {
            match TotpvaultDev::delete_credential(device, cli.timeout, args.domain_name.as_str()) {
                Ok(_) => println!("Successfully deleted credential"),
                Err(error) => eprintln!("Error deleting credential \"{}\": {}", args.domain_name, error),
            }
        }
        Commands::AddCredential(args) => {
            let mut totp_secret = rpassword::prompt_password("Enter TOTP Secret Key: ").unwrap();

            // Strip out spaces as some websites (Gmail) have spaces in the secret
            totp_secret = totp_secret.replace(" ", "");

            if let Err(e) = totpvault_lib::validate_totp_secret(totp_secret.as_str()) {
                eprintln!("Err: {}", e);
            } else {
                match TotpvaultDev::add_credential(device, cli.timeout, args.domain_name.as_str(), totp_secret.as_str()) {
                    Ok(_) => println!("Successfully added credential"),
                    Err(error) => eprintln!("{}", error),
                }
                totp_secret.zeroize();
            }
        }
        Commands::TotpCode(args) => {
            match TotpvaultDev::get_totp_code(device, cli.timeout, args.domain_name.as_str()) {
                Ok(totp_msg) => {
                    // Check if the device is in sync, warn the user if not
                    if !TotpvaultDev::timesync_check(totp_msg.system_timestamp) {
                        warn!("TOTPVault device time is not in sync! Codes will not be correct, sync with 'sync-time' command");
                    }
                    let time_remaining = TotpvaultDev::get_remaining_totp_ticks();
                    if time_remaining < 5.0 {
                        println!("{}\n{}s remaining", totp_msg.totp_code.green(), time_remaining.to_string().red());
                    } else {
                        println!("{}\n{}s remaining", totp_msg.totp_code.green(), time_remaining);
                    }
                }
                Err(error) => eprintln!("{}: {}", args.domain_name, error),
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

                if p1.len() == 0 || p2.len() == 0 {
                    eprintln!("Did not enter a password");
                }
                else if p1 == p2 {
                    match TotpvaultDev::init_vault(&device, cli.timeout, &p1) {
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
            match TotpvaultDev::get_device_status(device, cli.timeout) {
                Ok(device_status) => {
                    dump_device_status(&device_status);
                },
                Err(error) => eprintln!("Unable to get device status from: {}\n\tError = {}", device, error),
            }
        }
        Commands::AttestDev(args) => {
            let pub_key_b64 = match args.public_key {
                Some(key) => key,
                None => {
                    println!("No key specified, getting public key from device...");
                    match TotpvaultDev::get_device_status(device, cli.timeout) {
                        Ok(device_status) => device_status.public_key,
                        Err(error) => {
                            eprintln!("Unable to get device status from: {}\n\tError = {}", device, error);
                            return;
                        }
                    }
                }
            };

            match TotpvaultDev::public_key_to_hash(&pub_key_b64) {
                Ok(pub_key_hash) => {
                    println!("Public key: {}\nFingerprint (SHA256): {}", pub_key_b64.yellow(), pub_key_hash.yellow());
                    match TotpvaultDev::attest_device(device, cli.timeout, &pub_key_b64) {
                        Ok(_) => println!("{}", "Successfully attested device".green()),
                        Err(msg) => {
                            eprintln!("{}", "Failed to attest device!".to_string().red());
                            debug!("Attestation error message: {}", msg);
                        },
                    }
                },
                Err(error) => eprintln!("Invalid base64 public key: {}", error),
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

            if password.len() == 0 {
                eprintln!("Did not enter a password");
            }
            else {
                match TotpvaultDev::unlock_vault(device, cli.timeout, &password) {
                    Ok(_) => println!("Successfully unlocked vault"),
                    Err(error) => eprintln!("Error unlocking vault\n\tError = {}", error),
                }
            }
            
            password.zeroize();
        }
        Commands::LockVault => {
            match TotpvaultDev::lock_vault(device, cli.timeout) {
                Ok(_) => println!("{}", "Locked vault".green()),
                Err(error) => eprintln!("Error locking vault: {}", error),
            }
        }
    }
}
