use core::cell::Cell;
use std::collections::HashMap;
use std::fmt::Debug;
use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use chrono::Utc;
use credential::{Credential, MAX_CREDENTIALS};
use crypto::{get_ed25519_public_key_nvs, sign_challenge, gen_ed25519_keypair, gen_salt};
use ed25519_dalek::SECRET_KEY_LENGTH;
use esp_idf_svc::{
    hal::{gpio::AnyIOPin, prelude::Peripherals, reset::restart, uart, units::Hertz},
    sys,
};
use esp_idf_svc::hal::gpio::{Gpio10, InterruptType, Output, PinDriver, Pull};
use log::{error, info};
use pbkdf2;
use rmp_serde::Serializer;
use serde::Serialize;
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::Zeroize;
use totpvault_lib;
use critical_section::Mutex;
use esp_idf_svc::hal::timer::{TimerConfig, TimerDriver};
use storage::*;
use totpvault_lib::*;

mod credential;
mod crypto;
mod storage;

const SALT_LEN: usize = 32; // 256 bits
const KDF_ROUNDS: u32 = 100;

const ENCRYPTION_MAGIC: [u8; 8] = [0xDE, 0xAD, 0xBE, 0xEF, 0xC0, 0xFF, 0xEE, 0x00];

const MAX_TIMESTAMP_SET_DELTA: u64 = 1024;
const NVS_KEY_ED25519: &str = "ED25519_KEY";

// Static (global) variable for 'static lifetime. Mutex for safety, Cell<bool> allows multiple mutable references by only allowing 'interior mutability'
static VAULT_STATUS_UNLOCKED: Mutex<Cell<bool>> = Mutex::new(Cell::new(false));
struct System {
    time_set: bool,
    key: [u8; 32],
    settings: HashMap<String, String>,
}

impl System {
    fn new() -> System {
        System {
            time_set: false,
            key: [0; 32],
            settings: HashMap::new(),
        }
    }

    fn load_settings(&mut self) {
        // Iterate through all of the known settings by their NVS keys
        for key in ALL_SETTINGS {
            match nvs_read_setting(key) {
                Ok(value) => {
                    self.settings.insert(key.to_string(), value);
                },
                Err(_) => {
                    // If setting not found in the NVS, initialize with default and save
                    let default_value = match key {
                        SETTING_AUTOLOCK => AUTOLOCK_OFF,
                        _ => {
                            error!("Unknown setting key during load: {}", key);
                            continue; // Skip unknown settings
                        }
                    };
                    if let Err(write_err) = nvs_write_setting(key, default_value) {
                        error!("Failed to write default setting {} = {}: {}", key, default_value, write_err);
                    } else {
                        self.settings.insert(key.to_string(), default_value.to_string());
                    }
                }
            }
        }
    }

    fn set_setting(&mut self, set_msg: &SetSettingMsg) -> Result<(), String> {
        if !set_msg.validate() {
            return Err("Invalid setting key or value".to_string());
        }

        // Update in NVS
        nvs_write_setting(&set_msg.key, &set_msg.value)?;

        // Update in current system state
        self.settings.insert(set_msg.key.to_string(), set_msg.value.to_string());

        Ok(())
    }

    fn get_all_settings(&self) -> GetSettingsResponseMsg {
        GetSettingsResponseMsg {
            settings: self.settings.clone(),
        }
    }

    fn setup_ed25519() -> Result<(), String> {
        let mut secret_bytes: [u8; SECRET_KEY_LENGTH] = gen_ed25519_keypair().to_bytes();
        nvs_write_blob(NVS_KEY_ED25519, &secret_bytes)?;
        secret_bytes.zeroize();
        Ok(())
    }

    fn init_vault(&mut self, cmd_buf: &[u8; 512], _read_bytes: usize) -> Result<(), String> {
        let init_msg = rmp_serde::from_slice::<InitVaultMsg>(&cmd_buf[1..]).map_err(|e| format!("Invalid InitVault message: {}", e))?;

        if !init_msg.validate() {
            return Err("Invalid InitVault message".to_string());
        }

        critical_section::with(|cs| VAULT_STATUS_UNLOCKED.borrow(cs).set(false));

        // Erase NVS partition
        format_nvs_partition()?;
        Self::setup_ed25519()?;

        // Generate encryption salt and store it in the database
        let salt = gen_salt();
        nvs_write_blob("salt", &salt)?;

        // Derive the encryption key
        let enc_key = Self::derive_encryption_key(init_msg.password.as_str(), &salt);

        // Wipe all entries
        for i in 0..MAX_CREDENTIALS {
            Credential::init_credential(i)?;
        }

        // Init metadata
        nvs_write_blob_encrypted("magic", &ENCRYPTION_MAGIC, &enc_key)?;

        Ok(())
    }

    fn attest(&mut self, challenge_msg_bytes: &[u8]) -> Result<AttestationResponseMsg, String> {
        let challenge_msg = rmp_serde::from_slice::<AuthenticateChallengeMsg>(&challenge_msg_bytes[1..]).
            map_err(|_| "Invalid AuthenticateChallenge message")?;
        if !challenge_msg.validate() {
            return Err("Invalid AuthenticateChallenge message".to_string());
        }

        let challenge_bytes_vec  = BASE64_STANDARD.decode(challenge_msg.nonce_challenge.clone()).
            map_err(|_| "Invalid AuthenticateChallenge message")?;

        let challenge_bytes: [u8; NONCE_CHALLENGE_LEN] = challenge_bytes_vec.try_into().
            map_err(|_| "Invalid AuthenticateChallenge message")?;

        match sign_challenge(&challenge_bytes) {
            Ok(sig) => {
                let signature_encoded = BASE64_STANDARD.encode(sig.to_vec());
                Ok(AttestationResponseMsg{ message: signature_encoded })
            }
            Err(e) => Err(format!("Error signing challenge! {}", e))
        }
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
                cred.totp_secret_decrypted.zeroize();
                Ok(totp_code)
            }
            Err(_e) => {
                Err("Invalid display code message".to_string())
            }
        }
    }

    pub fn unlock_vault(&mut self, cmd_buf: &[u8; 512], _read_bytes: usize, unlocked_led: &mut PinDriver<Gpio10, Output>) -> Result<(), String> {
        let unlock_msg = rmp_serde::from_slice::<UnlockMsg>(&cmd_buf[1..]).map_err(|_| "Invalid Unlock message".to_string())?;

        if !unlock_msg.validate() {
            return Err("Invalid Unlock message".to_string());
        }

        // Read the salt, toss error if it fails ("?"), then try and convert into slice with SALT_LEN and handle error if it fails
        let salt: [u8; SALT_LEN] = match nvs_read_blob("salt")?.try_into() {
            Ok(v) => v,
            Err(_) => {
                return Err("Database is corrupted, salt is not a valid length. Please reset the database!".to_string());
            }
        };

        let key = Self::derive_encryption_key(unlock_msg.password.as_str(), &salt);

        // Test if the vault is unlocked
        let decrypted_magic = nvs_read_blob_encrypted("magic", &key).map_err(|_| "Unable to decrypt value. Corrupted data or wrong password!".to_string())?;

        // Use constant time compare for security, although it's not necessary maybe
        if decrypted_magic.ct_ne(&ENCRYPTION_MAGIC).unwrap_u8() == 1 {
            return Err("Invalid password".to_string());
        }

        self.key = key;
        critical_section::with(|cs| VAULT_STATUS_UNLOCKED.borrow(cs).set(true));

        // Set board LED GPIO10 to on for unlocked
        unlocked_led.set_high().unwrap();
        Ok(())
    }

    fn set_time(&mut self, cmd_buf: &[u8; 512], _read_bytes: usize) -> Result<(), String> {
        let time_msg = rmp_serde::from_slice::<SetTimeMsg>(&cmd_buf[1..]).map_err(|_| "Invalid SetTime message".to_string())?;

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
            cred.domain_name = create_msg.domain_name.clone();
            cred.totp_secret_decrypted = Some(create_msg.totp_secret.clone());

            // Save the credential
            Credential::save_credential(&mut cred, &self.key)?;
            cred.totp_secret_decrypted.zeroize();
        } else {
            return Err("Invalid CreateEntryMsg message".to_string());
        }
        Ok(())
    }
    fn first_boot_hook() -> Result<(), String> {
        // If we don't have a ED25519 private key setup, then this is the first boot
        match nvs_read_blob(NVS_KEY_ED25519) {
            Ok(_) => {}
            Err(_) => {
                // Erase NVS partition
                format_nvs_partition()?;
                // Setup ED25519 Key
                Self::setup_ed25519()?;
            }
        }
        Ok(())
    }

    fn get_system_info(&self) -> Result<SystemInfoMsg, String> {
        let pubkey = get_ed25519_public_key_nvs().map_err(|e| format!("Unable to get device public key. {}", e))?;

        let mut info_msg = SystemInfoMsg {
            total_slots: MAX_CREDENTIALS,
            used_slots: 0,
            free_slots: 0,
            current_timestamp: Utc::now().timestamp() as u64,
            version_str: format!("TOTPVault Version {}", env!("CARGO_PKG_VERSION")),
            vault_unlocked: get_vault_unlock_status(),
            public_key: pubkey,
        };

        if get_vault_unlock_status() {
            let num_used_creds = Credential::get_num_used_credentials(&self.key).map_err(|e| format!("Unable to enumerate stored credentials. {}", e))?;
            info_msg.used_slots = num_used_creds;
            info_msg.free_slots = MAX_CREDENTIALS - num_used_creds;
        }
        Ok(info_msg)
    }
}

pub fn send_message<T: Message + Serialize + Debug>(uart: &mut uart::UartDriver, msg: &T) {
    let mut buf = Vec::new();
    buf.push(msg.message_type_byte()); // Add the message type byte to the beginning

    // Add the remaining bytes into the buffer
    let m = msg.serialize(&mut Serializer::new(&mut buf));
    if m.is_err() {
        println!("Error serializing message: {}", m.unwrap_err());
    } else {
        uart.write(&buf).unwrap();
    }
}

pub fn send_response_message(uart: &mut uart::UartDriver, msg: &str, error: bool) {
    let status_msg = StatusMsg { error, message: msg.to_string() };
    send_message(uart, &status_msg);
}

fn get_vault_unlock_status() -> bool {
    critical_section::with(|cs| {
        VAULT_STATUS_UNLOCKED.borrow(cs).get()
    })
}

fn arm_auto_lock_timer(autolock_timer: &mut TimerDriver) -> () {
    autolock_timer.set_alarm(autolock_timer.tick_hz() * 60).unwrap();
    autolock_timer.set_counter(0).unwrap();
    autolock_timer.enable_interrupt().unwrap();
    autolock_timer.enable_alarm(true).unwrap();
    autolock_timer.enable(true).unwrap();
}
fn main() {
    // It is necessary to call this function once, otherwise some patches to the runtime
    // implemented by esp-idf-sys might not link properly. See https://github.com/esp-rs/esp-idf-template/issues/71
    esp_idf_svc::sys::link_patches();
    esp_idf_svc::log::EspLogger::initialize_default();

    #[cfg(debug_assertions)]
    std::env::set_var("RUST_BACKTRACE", "1");

    // Enable HW RNG. We are not using RF, so we need to use the ADC to feed the RNG. https://docs.espressif.com/projects/esp-idf/en/stable/esp32/api-reference/system/random.html#_CPPv424bootloader_random_enablev
    unsafe {
        sys::bootloader_random_enable();
    }
    info!("Hardware RNG enabled");

    let mut sys = System::new();
    sys.load_settings(); // Load settings on system initialization

    let peripherals = Peripherals::take().unwrap();

    let config = uart::config::Config::default()
        .baudrate(Hertz(115_200))
        .flow_control(uart::config::FlowControl::None);

    // Setup status LED and lock button
    let mut unlocked_led = PinDriver::output(peripherals.pins.gpio10).unwrap();
    unlocked_led.set_low().unwrap();
    let mut lock_button = PinDriver::input(peripherals.pins.gpio9).unwrap();
    lock_button.set_pull(Pull::Up).unwrap(); // Pull "BOOT" button up
    lock_button.set_interrupt_type(InterruptType::PosEdge).unwrap();

    // Lock button handler
    unsafe {
        lock_button.subscribe(|| {
            // Update the vault status inside a critical section (interrupts disabled) so nothing else can interrupt us
            critical_section::with(|cs| {
                let f = VAULT_STATUS_UNLOCKED.borrow(cs);
                f.set(false);
            });
        }).unwrap();
    }

    lock_button.enable_interrupt().unwrap();

    let timer_config = TimerConfig::new().divider(160).auto_reload(false); // Divider = 160 since ESP32-C3 runs @ 160MHz. Auto-reload = false for one-shot timer
    let mut autolock_timer = TimerDriver::new(peripherals.timer00, &timer_config).unwrap();
    unsafe {
    autolock_timer.subscribe(|| {
        critical_section::with(|cs| {
            let f = VAULT_STATUS_UNLOCKED.borrow(cs);
            f.set(false);
            });
        }).unwrap();
    }

    if let Err(e) = System::first_boot_hook() {
        error!("Critical error on first boot! {e}");
        restart();
    }

    // After this line, logging stops working as UART is taken over for host <-> dev communication
    let mut uart: uart::UartDriver = uart::UartDriver::new(
        peripherals.uart1,
        peripherals.pins.gpio21,
        peripherals.pins.gpio20,
        Option::<AnyIOPin>::None,
        Option::<AnyIOPin>::None,
        &config,
    ).expect("Error initializing UART Driver");

    loop {
        std::thread::sleep(std::time::Duration::from_millis(100));

        // Update vault locked LED
        match get_vault_unlock_status() {
            true => unlocked_led.set_high().unwrap(),
            false => unlocked_led.set_low().unwrap(),
        }

        let mut buf: [u8; 512] = [0; 512];
        if let Ok(num_bytes_read) = uart.read(&mut buf, 10) {
            if num_bytes_read > 0 {
                let command = buf[0];

                // Only the CMD_LOCK_VAULT, CMD_DEV_INFO, CMD_LIST, CMD_GET_SETTINGS commands are one byte, the rest should be 2+ bytes
                let min_required_len = match command {
                    CMD_LOCK_VAULT | CMD_DEV_INFO | CMD_LIST | CMD_GET_SETTINGS => 1,
                    _ =>  2,
                };
                if num_bytes_read < min_required_len {
                    send_response_message(&mut uart, "Invalid command length", true);
                    continue;
                }

                match command {
                    CMD_SET_TIME => {
                        if get_vault_unlock_status() == false {
                            send_response_message(&mut uart, "Vault Locked!", true)
                        } else {
                            match sys.set_time(&buf, num_bytes_read) {
                                Ok(_) => send_response_message(&mut uart, SUCCESS_MSG, false),
                                Err(e) => send_response_message(&mut uart, e.as_str(), true),
                            }
                        }
                    },
                    CMD_CREATE => {
                        if get_vault_unlock_status() == false  {
                            send_response_message(&mut uart, "Vault Locked!", true)
                        } else {
                            match sys.create_entry(&buf, num_bytes_read) {
                                Ok(_) => send_response_message(&mut uart, SUCCESS_MSG, false),
                                Err(e) => send_response_message(&mut uart, e.as_str(), true),
                            }
                        }
                    }
                    CMD_LIST => {
                        if get_vault_unlock_status() == false {
                            send_response_message(&mut uart, "Vault Locked!", true)
                        } else {
                            match Credential::list_credentials(&sys.key) {
                                Ok(creds) => {
                                    // Transform them into CredentialListMsg
                                    let creds_vec = creds.iter().map(|cred| CredentialInfo { domain_name: cred.domain_name.clone(), slot_id: cred.slot_id }).collect();
                                    let cred_list_msg = CredentialListMsg { credentials: creds_vec };
                                    send_message(&mut uart, &cred_list_msg);
                                }
                                Err(e) => send_response_message(&mut uart, e.as_str(), true),
                            }
                        }
                    }
                    CMD_DELETE => {
                        if get_vault_unlock_status() == false  {
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
                        if get_vault_unlock_status() == false  {
                            send_response_message(&mut uart, "Vault Locked!", true)
                        } else {
                            match sys.display_code(&buf) {
                                Ok(totp_code) => {
                                    let totp_code_msg = TOTPCodeMsg { totp_code: totp_code, system_timestamp: Utc::now().timestamp() as u64 };
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
                        match sys.unlock_vault(&buf, num_bytes_read, &mut unlocked_led) {
                            Ok(_) => {
                                // Check if we have auto-lock enabled, if yes load and fire the lock timer
                                if let Ok(auto_lock_setting) = nvs_read_setting(SETTING_AUTOLOCK) {
                                    if auto_lock_setting == AUTOLOCK_ON {
                                        arm_auto_lock_timer(&mut autolock_timer);
                                    }
                                }
                                send_response_message(&mut uart, SUCCESS_MSG, false)
                            },
                            Err(_) => send_response_message(&mut uart, "Incorrect Password", true),
                        };
                    }
                    CMD_INIT_VAULT => match sys.init_vault(&buf, num_bytes_read) {
                        Ok(_) => send_response_message(&mut uart, SUCCESS_MSG, false),
                        Err(e) => send_response_message(&mut uart, e.as_str(), true),
                    },
                    CMD_ATTEST => {
                        // Generate pub/priv keypair during vault init or first boot (?) if first boot, we have to make sure we NEVER wipe it! Maybe store in eFuse
                        // Respond to a challenge and authenticate the HW to avoid evil maid attacks
                        match sys.attest(&buf) {
                            Ok(attestation_response_msg) => {
                                send_message(&mut uart, &attestation_response_msg);
                            },
                            Err(e) => send_response_message(&mut uart, e.as_str(), true),
                        }
                    }
                    CMD_LOCK_VAULT => {
                        critical_section::with(|cs| VAULT_STATUS_UNLOCKED.borrow(cs).set(false));
                        sys.key.zeroize();
                        unlocked_led.set_low().unwrap();
                        send_response_message(&mut uart, SUCCESS_MSG, false);
                    }
                    CMD_GET_SETTINGS => {
                        let response_msg = sys.get_all_settings();
                        send_message(&mut uart, &response_msg);
                    }
                    CMD_SET_SETTINGS => {
                        if get_vault_unlock_status() == false {
                            send_response_message(&mut uart, "Vault Locked!", true);
                        } else {
                            match rmp_serde::from_slice::<SetSettingMsg>(&buf[1..]) {
                                Ok(set_msg) => {
                                    match sys.set_setting(&set_msg) {
                                        Ok(_) => send_response_message(&mut uart, SUCCESS_MSG, false),
                                        Err(e) => send_response_message(&mut uart, e.as_str(), true),
                                    }
                                }
                                Err(_e) => {
                                    send_response_message(&mut uart, "Invalid SetSetting message", true);
                                }
                            }
                        }
                    }
                    _ => {
                        send_response_message(&mut uart, format!("Unknown command: {:#02x}", command).as_str(), true);
                    }
                }
            }
        }
    }
}
