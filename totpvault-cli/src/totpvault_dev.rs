const VID: u16 = 0x1a86;
const PID: u16 = 0x55d3;
const ALLOWED_TIMESYNC_DELTA: i64 = 10;
use std::{env};
use rmp_serde::{Deserializer};
use serialport;
use serde::{Deserialize};
use std::io::Cursor;
use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use chrono::Utc;
use log::{debug, info};
use serialport::{SerialPortType};
use sha2::{Digest, Sha256};
use crate::*;
use totpvault_lib::*;
use crate::totpvault_comm::{check_status_msg, send_command, send_message};

pub struct TotpvaultDev {

}

impl TotpvaultDev {
    pub fn timesync_check(device_timestamp: u64) -> bool {
        let current_time = Utc::now().timestamp() as u64;
        let time_delta = ((current_time - device_timestamp) as i64).abs();

        info!("System time (UTC): {}     Device time (UTC): {}     Delta: {}", current_time, device_timestamp, time_delta);
        if time_delta > ALLOWED_TIMESYNC_DELTA {
            return false
        }
        true
    }

    pub fn get_remaining_totp_ticks() -> f64 {
        let ts = Utc::now();
        (30 - (ts.timestamp() % 30)) as f64
    }

    pub fn public_key_to_hash(b64_publickey: &str) -> Result<String, String> {
        let decoded = BASE64_STANDARD.decode(b64_publickey).map_err(|e| e.to_string())?;
        let digest = Sha256::digest(decoded);

        let hash_str = hex::encode(digest);
        let mut formatted = String::from("");
        for chunk in hash_str.chars().collect::<Vec<char>>().chunks(2) {
            formatted += format!("{}{}:", chunk[0], chunk[1]).as_str();
        }
        if formatted.chars().last().unwrap() == ':' {
            formatted = formatted[..formatted.len()-1].to_string();
        }
        formatted = formatted.to_uppercase();
        Ok(formatted)
    }

    pub fn find_device() -> Result<String, String> {
        match serialport::available_ports() {
            Ok(ports) => {
                for port in ports {
                    match port.port_type {
                        SerialPortType::UsbPort(info) => {
                            if info.vid == VID && info.pid == PID {
                                // Handle OS-specific details
                                match env::consts::OS {
                                    "windows" => {
                                        // TODO
                                    }
                                    "linux" => {
                                        debug!("Using USB device {:02x}:{:02x} @ {}", info.vid, info.pid, port.port_name);
                                        return Ok(port.port_name);
                                    }
                                    "macos" => {
                                        if port.port_name.contains("tty") {
                                            debug!("Using USB device {:02x}:{:02x} @ {}", info.vid, info.pid, port.port_name);
                                            return Ok(port.port_name);
                                        } else {
                                            debug!("Skipping non-tty port: {}", port.port_name);
                                        }
                                    }
                                    _ => {}
                                }
                            }
                            else {
                                debug!("Skipping USB device {:02x} {:02x}", info.vid, info.pid);
                            }
                        }
                        _ => {}
                    }
                }
            }
            Err(e) => return Err(e.to_string())
        }
        Err("No TOTP devices found.".to_string())
    }

    pub fn get_device_status(dev_path: &str) -> Result<SystemInfoMsg, String> {
        let resp = send_command(dev_path, CMD_DEV_INFO)?;
        // Check that we got a valid SYSINFO message
        if resp[0] != MSG_SYSINFO {
            // Dump error out
            if resp[0] == MSG_STATUS_MSG {
                let msg: StatusMsg = Deserialize::deserialize(&mut Deserializer::new(&resp[1..])).map_err(|e| e.to_string())?;
                return Err(format!("Error getting device status: {}", msg.message));
            }
            else {
                return Err("Invalid response message from device!".to_string());
            }
        }
        let mut cursor_buf = Cursor::new(resp[1..].to_vec());
        let msg: SystemInfoMsg = Deserialize::deserialize(&mut Deserializer::new(& mut cursor_buf)).map_err(|e| e.to_string())?;

        Ok(msg)
    }
    
    pub fn list_stored_credentials(dev_path: &str) -> Result<Vec<CredentialInfo>, String> {
        let resp = send_command(dev_path, CMD_LIST)?;
        if resp[0] == MSG_LIST_CREDS {
            let creds: Vec<CredentialInfo> = Deserialize::deserialize(&mut Deserializer::new(&resp[1..])).map_err(|e| e.to_string())?;
            Ok(creds)
        } else {
            if resp[0] == MSG_STATUS_MSG {
                let msg: StatusMsg = Deserialize::deserialize(&mut Deserializer::new(&resp[1..])).map_err(|e| e.to_string())?;
                return Err(format!("Error getting device status: {}", msg.message));
            }
            else {
                return Err("Invalid response message from device!".to_string());
            }
        }
    }
    
    pub fn get_totp_code(dev_path: &str, credential: &CredentialInfo) -> Result<String, String> {
        // TODO: complete. Change in Firmware to display the TOTP code with the listing of credentials to reduce time
        Ok("12345".to_string())
    }
    
    pub fn add_credential(dev_path: &str, domain_name: &str, totp_secret: &str) -> Result<(), String> {
        match send_message(dev_path, CreateEntryMsg{domain_name: domain_name.to_string(), totp_secret: totp_secret.to_string()}, CMD_CREATE) {
            Ok(_) => Ok(()),
            Err(_) => Err("Failed to create credential! Check logs".to_string())
        }
    }
    pub fn delete_credential(dev_path: &str, domain_name: &str) -> Result<(), String> {
        match send_message(dev_path, DeleteEntryMsg{domain_name: domain_name.to_string()}, CMD_DELETE) {
            Ok(_) => Ok(()),
            Err(_) => Err("Failed to delete credential! Check logs".to_string())
        }
    }

    pub fn unlock_vault(dev_path: &str, password: &str) -> Result<(), String> {
        match send_message(dev_path, UnlockMsg{password: password.to_string()}, CMD_UNLOCK_VAULT) {
            Ok(_) => Ok(()),
            Err(e) => Err(format!("Failed to unlock the vault! Bad password? Err: {}", e))
        }
    }

    pub fn init_vault(dev_path: &str, password: &str) -> Result<(), String> {
        let msg = InitVaultMsg{password: password.to_string()};
        if !msg.validate() {
            Err(format!("Password does not meet the criteria of {}-{} characters", MIN_PW_LEN, MAX_PW_LEN))
        }
        else {
            let res = send_message(dev_path, msg, CMD_INIT_VAULT)?;
            check_status_msg(res)
        }

    }
    pub fn sync_time(dev_path: &str) -> Result<(), String> {
        let res = send_message(dev_path, SetTimeMsg{unix_timestamp: Utc::now().timestamp() as u64}, CMD_SET_TIME)?;
        check_status_msg(res)
    }

    pub fn lock_vault(dev_path: &str) -> Result<(), String> {
        let resp = send_command(dev_path, CMD_LOCK_VAULT)?;
        check_status_msg(resp)
    }
}