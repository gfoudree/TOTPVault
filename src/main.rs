use chrono::Utc;
use credential::{Credential, MAX_CREDENTIALS};
use crypto::{get_pubkey, sign_challenge};
use ed25519_dalek::{SigningKey, SECRET_KEY_LENGTH};
use esp_idf_svc::{
    hal::{gpio::AnyIOPin, prelude::Peripherals, reset::restart, uart, units::Hertz},
    sys,
};
use esp_idf_sys::{nvs_get_stats, nvs_stats_t, ESP_OK};
use pbkdf2;
use rand::rngs::OsRng;
use rand::RngCore;
use rmp_serde::Serializer;
use serde::Serialize;
use sha2::Sha256;
use std::fmt::Write;
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use comm::*;
use storage::*;

mod comm;
mod credential;
mod crypto;
mod storage;

const CMD_SET_TIME: u8 = 0x10;
const CMD_CREATE: u8 = 0x11;
const CMD_LIST: u8 = 0x12;
const CMD_DELETE: u8 = 0x13;
const CMD_DISPLAY_CODE: u8 = 0x14;
const CMD_DEV_INFO: u8 = 0x15;
const CMD_UNLOCK_VAULT: u8 = 0x1A;
const CMD_INIT_VAULT: u8 = 0x1B;
const CMD_ATTEST: u8 = 0x1C;
const CMD_LOCK_VAULT: u8 = 0x1E;
pub const MSG_STATUS_MSG: u8 = 0x01;
pub const MSG_SYSINFO: u8 = 0x20;
pub const MSG_ATTESTATION_RESPONSE: u8 = 0x21;
pub const MSG_LIST_CREDS: u8 = 0x22;
pub const MSG_TOTP_CODE: u8 = 0x23;
const SALT_LEN: usize = 32; // 256 bits
const KDF_ROUNDS: u32 = 100;

const ENCRYPTION_MAGIC: [u8; 8] = [0xDE, 0xAD, 0xBE, 0xEF, 0xC0, 0xFF, 0xEE, 0x00];

const MAX_TIMESTAMP_SET_DELTA: u64 = 1024;

const NVS_KEY_ED25519: &str = "ED25519_KEY";

struct System {
    vault_unlocked: bool,
    time_set: bool,
    key: [u8; 32],
}

impl System {
    fn new() -> System {
        System {
            vault_unlocked: false,
            time_set: false,
            key: [0; 32],
        }
    }

    fn gen_salt() -> [u8; SALT_LEN] {
        let mut buffer = [0u8; SALT_LEN]; // Create a buffer of SALT_LEN
        let mut rng = OsRng; // Create a new instance of OsRng

        rng.fill_bytes(&mut buffer); // Verified via radare to call esp_fill_random()
        buffer
    }

    fn setup_uart<'a>(&mut self) -> uart::UartDriver<'a> {
        let peripherals = Peripherals::take().unwrap();

        let config = uart::config::Config::default()
            .baudrate(Hertz(115_200))
            .flow_control(uart::config::FlowControl::None);
        let pins = peripherals.pins;

        let uart: uart::UartDriver = uart::UartDriver::new(
            peripherals.uart1,
            pins.gpio16,
            pins.gpio17,
            Option::<AnyIOPin>::None,
            Option::<AnyIOPin>::None,
            &config,
        )
            .expect("Error initializing UART Driver");

        uart
    }

    fn setup_ed25519() -> Result<(), String> {
        let mut rng = OsRng;
        let key: SigningKey = SigningKey::generate(&mut rng);

        let mut secret_bytes: [u8; SECRET_KEY_LENGTH] = key.to_bytes();
        nvs_write_blob(NVS_KEY_ED25519, &secret_bytes)?;
        secret_bytes.zeroize();
        Ok(())
    }

    fn init_vault(&mut self, cmd_buf: &[u8; 512], _read_bytes: usize) -> Result<(), String> {
        let init_msg = rmp_serde::from_slice::<InitVaultMsg>(&cmd_buf[1..]).map_err(|_| format!("Invalid InitVault message"))?;

        if !init_msg.validate() {
            return Err("Invalid InitVault message".to_string());
        }

        // Generate encryption salt and store it in the database
        let salt = Self::gen_salt();
        nvs_write_blob("salt", &salt)?;

        // Derive the encryption key
        let enc_key = Self::derive_encryption_key(init_msg.password.as_str(), &salt);
        #[cfg(debug_assertions)]
        {
            println!("Init Salt: {:02X?}", salt);
            println!("Init Key: {:02X?}", enc_key);
            println!("Pw: {:02X?}", init_msg.password);
        }

        // Wipe all entries
        for i in 0..MAX_CREDENTIALS {
            Credential::init_credential(i)?;
        }

        // Init metadata
        nvs_write_blob_encrypted("magic", &ENCRYPTION_MAGIC, &enc_key)?;

        #[cfg(debug_assertions)] {
            let mut stats: nvs_stats_t = Default::default();
            unsafe {
                let res = nvs_get_stats(core::ptr::null_mut(), &mut stats);
                if res != ESP_OK {
                    println!("Error calling nvs_get_stats!");
                } else {
                    println!("NVS Stats:\nFreeEntries: {}\n UsedEntries: {}\nAvailable Entries: {}\nAll Entries: {}", stats.free_entries, stats.used_entries, stats.available_entries, stats.total_entries);
                }
            }
        }

        Ok(())
    }

    fn derive_encryption_key(password: &str, salt: &[u8; SALT_LEN]) -> [u8; 32] {
        let key = pbkdf2::pbkdf2_hmac_array::<Sha256, 32>(
            password.as_bytes(),
            salt,
            KDF_ROUNDS,
        );

        key
    }

    fn display_code(&self, cmd_buf: &[u8; 512]) -> Result<String, String> {
        if self.time_set == false {
            return Err("System time has not been set!".to_string());
        }

        match rmp_serde::from_slice::<DisplayCodeMsg>(&cmd_buf[1..]) {
            Ok(display_code_msg) => {
                let index = Credential::credential_name_to_index(display_code_msg.domain_name, &self.key)?;
                let mut cred = Credential::get_credential(index, &self.key)?;

                let totp_code = Credential::gen_totp(&cred)?;
                #[cfg(debug_assertions)]
                {
                    println!("[TOTP] Current time: {}\t Secret Key: {}", Utc::now().timestamp(), &cred.totp_secret_decrypted.clone().unwrap());
                }
                cred.totp_secret_decrypted.zeroize();
                Ok(totp_code)
            }
            Err(e) => {
                #[cfg(debug_assertions)]
                {
                    println!("Unlock message decoding error: {:?}", e);
                }
                Err("Invalid display code message".to_string())
            }
        }
    }

    pub fn unlock_vault(&mut self, cmd_buf: &[u8; 512], _read_bytes: usize) -> Result<(), String> {
        let unlockmsg = rmp_serde::from_slice::<UnlockMsg>(&cmd_buf[1..]).map_err(|_| "Invalid Unlock message".to_string())?;

        if !unlockmsg.validate() {
            return Err("Invalid Unlock message".to_string());
        }

        // Read the salt, toss error if it fails ("?"), then try and convert into slice with SALT_LEN and handle error if it fails
        let salt: [u8; SALT_LEN] = match nvs_read_blob("salt")?.try_into() {
            Ok(v) => v,
            Err(_) => {
                return Err("Database is corrupted, salt is not a valid length. Please reset the database!".to_string());
            }
        };

        let key = Self::derive_encryption_key(unlockmsg.password.as_str(), &salt);

        #[cfg(debug_assertions)]
        {
            println!("Salt: {:02X?}", salt);
            println!("Key: {:02X?}", key);
            println!("Pw: {:02X?}", unlockmsg.password);
        }

        // Test if the vault is unlocked
        let decrypted_magic = nvs_read_blob_encrypted("magic", &key).map_err(|_| "Unable to decrypt value. Corrupted data or wrong password!".to_string())?;

        // Use constant time compare for security, although it's not necessary maybe
        if decrypted_magic.ct_ne(&ENCRYPTION_MAGIC).unwrap_u8() == 1 {
            return Err("Invalid password".to_string());
        }

        self.key = key;
        self.vault_unlocked = true;

        Ok(())
    }

    fn set_time(&mut self, cmd_buf: &[u8; 512], _read_bytes: usize) -> Result<(), String> {
        let time_msg = rmp_serde::from_slice::<SetTimeMsg>(&cmd_buf[1..]).map_err(|_| format!("Invalid SetTime message"))?;

        if !time_msg.validate() {
            return Err("Invalid SetTime message".to_string());
        }

        let new_unix_timestamp = time_msg.unix_timestamp;

        if self.time_set {
            // Time has been set already, check if the new time is more than the max allowed delta
            let mut current_tv = sys::timeval { tv_sec: 0, tv_usec: 0 };
            unsafe {
                sys::gettimeofday(&mut current_tv, core::ptr::null_mut());
            }

            // Is the new timestamp LESS than the current one OR is the difference between the new and old one > the allowed delta?
            if new_unix_timestamp < current_tv.tv_sec as u64 || (new_unix_timestamp - current_tv.tv_sec as u64) > MAX_TIMESTAMP_SET_DELTA {
                return Err("Invalid timestamp".to_string());
            }
        }

        let tv = sys::timeval {
            tv_sec: new_unix_timestamp as i64,
            tv_usec: 0,
        };
        let tz = sys::timezone {
            tz_minuteswest: 0,
            tz_dsttime: 0,
        };

        // Set the time
        let res: i32;
        unsafe {
            res = sys::settimeofday(&tv, &tz);
        }
        if res != 0 {
            Err("Unable to set time of day!".to_string())
        } else {
            self.time_set = true;
            Ok(())
        }
    }

    fn create_entry(&mut self, cmd_buf: &[u8; 512], _read_bytes: usize) -> Result<(), String> {
        let create_msg = rmp_serde::from_slice::<CreateEntryMsg>(&cmd_buf[1..]).map_err(|_| "Invalid CreateEntry message".to_string())?;

        // Check message fields to see if they're correct
        if create_msg.validate() {
            let mut cred = Credential::default();
            cred.in_use = true;
            cred.domain_name = create_msg.domain_name;
            cred.totp_secret_decrypted = Some(create_msg.totp_secret);

            // Save the credential
            Credential::save_credential(&mut cred, &self.key)?;
            cred.totp_secret_decrypted.zeroize();
        } else {
            return Err("Invalid CreateEntryMsg message".to_string());
        }
        Ok(())
    }
    fn first_boot_hook() -> Result<(), String> {
        // Erase NVS partition
        format_nvs_partition()?;
        // Setup ED25519 Key
        match nvs_read_blob(NVS_KEY_ED25519) {
            Ok(_) => {}
            Err(_) => {
                Self::setup_ed25519()?;
            }
        }
        Ok(())
    }

    fn get_system_info(&self) -> Result<SystemInfoMsg, String> {
        let pubkey = get_pubkey().map_err(|e| format!("Unable to get pubkey. {}", e))?;
        let mut info_msg = SystemInfoMsg {
            total_slots: MAX_CREDENTIALS,
            used_slots: 0,
            free_slots: 0,
            current_timestamp: Utc::now().timestamp() as u64,
            version_str: "2FA Cube Version 0.1".to_string(),
            vault_unlocked: self.vault_unlocked,
            public_key: pubkey,
        };

        if self.vault_unlocked {
            let num_used_creds = Credential::get_num_used_credentials(&self.key).map_err(|e| format!("Unable to enumerate stored credentials. {}", e))?;
            info_msg.used_slots = num_used_creds;
            info_msg.free_slots = MAX_CREDENTIALS - num_used_creds;
        }
        Ok(info_msg)
    }
}

pub fn send_message<T: Message + Serialize>(uart: &mut uart::UartDriver, msg: &T) {
    let mut buf = Vec::new();
    buf.push(msg.message_type_byte()); // Add the message type byte to the beginning

    msg.serialize(&mut Serializer::new(&mut buf)).unwrap(); // Add the remaining bytes into the buffer
    uart.write(&buf).unwrap();
}

pub fn send_response_message(uart: &mut uart::UartDriver, msg: &str, error: bool) {
    let status_msg = StatusMsg { error, message: msg.to_string() };
    send_message(uart, &status_msg);
}

fn main() {
    // It is necessary to call this function once. Otherwise some patches to the runtime
    // implemented by esp-idf-sys might not link properly. See https://github.com/esp-rs/esp-idf-template/issues/71
    esp_idf_svc::sys::link_patches();

    #[cfg(debug_assertions)]
    std::env::set_var("RUST_BACKTRACE", "1");

    // Enable HW RNG. We are not using RF, so we need to use the ADC to feed the RNG. https://docs.espressif.com/projects/esp-idf/en/stable/esp32/api-reference/system/random.html#_CPPv424bootloader_random_enablev
    unsafe {
        sys::bootloader_random_enable();
    }

    let mut sys = System::new();
    let mut uart = sys.setup_uart();

    if let Err(e) = System::first_boot_hook() {
        println!("Critical error on first boot! {e}");
        restart();
    }

    loop {
        std::thread::sleep(std::time::Duration::from_millis(100));

        let mut buf: [u8; 512] = [0; 512];
        let num = uart.read(&mut buf, 10).unwrap();
        if num > 0 {
            let command = buf[0];
            match command {
                CMD_SET_TIME => match sys.set_time(&buf, num) {
                    Ok(_) => send_response_message(&mut uart, SUCCESS_MSG, false),
                    Err(e) => send_response_message(&mut uart, e.as_str(), true),
                },
                CMD_CREATE => {
                    if sys.vault_unlocked == false {
                        send_response_message(&mut uart, "Vault Locked!", true)
                    } else {
                        match sys.create_entry(&buf, num) {
                            Ok(_) => send_response_message(&mut uart, SUCCESS_MSG, false),
                            Err(e) => send_response_message(&mut uart, e.as_str(), true),
                        }
                    }
                }
                CMD_LIST => {
                    if sys.vault_unlocked == false {
                        send_response_message(&mut uart, "Vault Locked!", true)
                    } else {
                        match Credential::list_credentials(&sys.key) {
                            Ok(creds) => {
                                // Transform them into CredentialListMsg
                                let cred_list_msg = CredentialListMsg { credentials: creds.iter().map(|cred| CredentialInfo { domain_name: cred.domain_name.clone(), slot_id: cred.slot_id }).collect() };
                                send_message(&mut uart, &cred_list_msg);
                            }
                            Err(e) => send_response_message(&mut uart, e.as_str(), true),
                        }
                    }
                }
                CMD_DELETE => {
                    if sys.vault_unlocked == false {
                        send_response_message(&mut uart, "Vault Locked!", true)
                    } else {
                        if let Ok(del_msg) = rmp_serde::from_slice::<DeleteEntryMsg>(&buf[1..]) {
                            if del_msg.validate() {
                                match Credential::delete_credential_by_name(del_msg.domain_name, &sys.key) {
                                    Ok(_) => send_response_message(&mut uart, SUCCESS_MSG, false),
                                    Err(e) => send_response_message(&mut uart, format!("Error deleting credential: {}", e).as_str(), true),
                                }
                            } else {
                                send_response_message(&mut uart, "Invalid DeleteMsg message", true);
                            }
                        } else {
                            send_response_message(&mut uart, "Invalid DeleteMsg message", true);
                        }
                    }
                }
                CMD_DISPLAY_CODE => {
                    if sys.vault_unlocked == false {
                        send_response_message(&mut uart, "Vault Locked!", true)
                    } else {
                        match sys.display_code(&buf) {
                            Ok(totp_code) => {
                                let totp_code_msg = TOTPCodeMsg { totp_code: totp_code };
                                send_message(&mut uart, &totp_code_msg);
                            }
                            Err(e) => send_response_message(&mut uart, format!("Error generating TOTP code: {}", e).as_str(), true),
                        }
                    }
                }
                CMD_DEV_INFO => {
                    match sys.get_system_info() {
                        Ok(sys_info) => send_message(&mut uart, &sys_info),
                        Err(e) => send_response_message(&mut uart, e.as_str(), true),
                    }
                }
                CMD_UNLOCK_VAULT => {
                    // TODO: use subtle crypto library when needed!
                    match sys.unlock_vault(&buf, num) {
                        Ok(_) => send_response_message(&mut uart, SUCCESS_MSG, false),
                        Err(_) => send_response_message(&mut uart, "Incorrect Password", true),
                    };
                }
                CMD_INIT_VAULT => match sys.init_vault(&buf, num) {
                    Ok(_) => send_response_message(&mut uart, SUCCESS_MSG, false),
                    Err(e) => send_response_message(&mut uart, e.as_str(), true),
                },
                CMD_ATTEST => {
                    // Generate pub/priv keypair during vault init or first boot (?) if first boot, we have to make sure we NEVER wipe it! Maybe store in eFuse
                    // Respond to a challenge and authenticate the HW to avoid evil maid attacks
                    // Use hardware digital signature module with ESP32
                    #[cfg(debug_assertions)]
                    println!("Challenge Raw Bytes: {}", hex::encode(&buf));

                    if let Ok(challenge_msg) = rmp_serde::from_slice::<AuthenticateChallengeMsg>(&buf[1..]) {
                        if challenge_msg.validate() {
                            let challenge_bytes: [u8; NONCE_CHALLENGE_LEN] = base64::decode(challenge_msg.nonce_challenge.clone()).unwrap().try_into().unwrap();
                            match sign_challenge(&challenge_bytes) {
                                Ok(sig) => {
                                    #[cfg(debug_assertions)] {
                                        println!("Public Key: {}\nChallenge: {}\nSignature: {}", get_pubkey().unwrap(), challenge_msg.nonce_challenge, sig);
                                    }
                                    let attestation_response_msg = AttestationResponseMsg { message: sig.to_string() };
                                    send_message(&mut uart, &attestation_response_msg);
                                }
                                Err(e) => send_response_message(&mut uart, format!("Error signing challenge! {}", e).as_str(), true),
                            }
                        } else {
                            send_response_message(&mut uart, "Invalid AuthenticateChallengeMsg message", true);
                        }
                    } else {
                        send_response_message(&mut uart, "Invalid AuthenticateChallengeMsg message", true);
                    }
                }
                CMD_LOCK_VAULT => {
                    sys.vault_unlocked = false;
                    sys.key.zeroize();
                    send_response_message(&mut uart, SUCCESS_MSG, false);
                }
                _ => {}
            }
        }
    }
}
