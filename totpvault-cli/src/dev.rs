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
use crate::comm::{check_status_msg, send_command, send_message};
use ed25519_dalek::{VerifyingKey, Signature, Verifier};

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
        // Window is 30s
        let ts = Utc::now();
        (30 - (ts.timestamp() % 30)) as f64
    }

    // Create SHA256 hash of base64-encoded public key
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
            let cred_list_msg: CredentialListMsg = Deserialize::deserialize(&mut Deserializer::new(&resp[1..])).map_err(|e| e.to_string())?;
            Ok(cred_list_msg.credentials)
        } else {
            if resp[0] == MSG_STATUS_MSG {
                let msg: StatusMsg = Deserialize::deserialize(&mut Deserializer::new(&resp[1..])).map_err(|e| e.to_string())?;
                Err(format!("Error getting device status: {}", msg.message))
            }
            else {
                Err("Invalid response message from device!".to_string())
            }
        }
    }

    pub fn get_totp_code(dev_path: &str, domain_name: &str) -> Result<String, String> {
        let resp = send_message(dev_path, DisplayCodeMsg{domain_name: domain_name.to_string()}, CMD_DISPLAY_CODE)?;
        if resp[0] == MSG_TOTP_CODE {
            let totp_code_msg: TOTPCodeMsg = Deserialize::deserialize(&mut Deserializer::new(&resp[1..])).map_err(|e| e.to_string())?;
            Ok(totp_code_msg.totp_code)
        } else {
            if resp[0] == MSG_STATUS_MSG {
                let msg: StatusMsg = Deserialize::deserialize(&mut Deserializer::new(&resp[1..])).map_err(|e| e.to_string())?;
                Err(format!("Error getting TOTP code: {}", msg.message))
            }
            else {
                Err("Invalid response message from device!".to_string())
            }
        }
    }

    pub fn add_credential(dev_path: &str, domain_name: &str, totp_secret: &str) -> Result<(), String> {
        match send_message(dev_path, CreateEntryMsg{domain_name: domain_name.to_string(), totp_secret: totp_secret.to_string()}, CMD_CREATE) {
            Ok(_) => Ok(()),
            Err(e) =>  {
                debug!("Error adding TOTP credential: {}", e);
                Err("Failed to create credential! Try with -v for more info".to_string())
            }
        }
    }
    pub fn delete_credential(dev_path: &str, domain_name: &str) -> Result<(), String> {
        match send_message(dev_path, DeleteEntryMsg{domain_name: domain_name.to_string()}, CMD_DELETE) {
            Ok(_) => Ok(()),
            Err(_) => Err("Failed to delete credential! Try with -v for more info".to_string())
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
        let res = send_command(dev_path, CMD_LOCK_VAULT)?;
        check_status_msg(res)
    }

    pub fn attest_device(dev_path: &str, pub_key_b64: &str) -> Result<(), String> {
        // Decode public key
        let pub_key = BASE64_STANDARD.decode(pub_key_b64).map_err(|e| format!("Error decoding public key: {}", e))?;
        let pub_key_bytes: [u8; 32] = pub_key.try_into().map_err(|_| "Public key not proper length!")?;

        // Generate random challenge
        let random_bytes: [u8; 64] = rand::random();
        let random_bytes_encoded = BASE64_STANDARD.encode(&random_bytes);

        let resp = send_message(dev_path, AuthenticateChallengeMsg{nonce_challenge: random_bytes_encoded}, CMD_ATTEST)?;
        if resp[0] == MSG_ATTESTATION_RESPONSE {
            let attestation_resp_msg: AttestationResponseMsg = Deserialize::deserialize(&mut Deserializer::new(&resp[1..])).map_err(|e| e.to_string())?;
            // Check the attestation message
            let attestation_reply_bytes = BASE64_STANDARD.decode(attestation_resp_msg.message).map_err(|e| e.to_string())?;

            debug!("Attestation:\nChallenge: {}\nResponse: {}\nDevice ED25519 Pubkey: {}", hex::encode(random_bytes.clone()), hex::encode(attestation_reply_bytes.clone()), hex::encode(pub_key_bytes.clone()));
            Self::ed25519_verify_signature(&pub_key_bytes, random_bytes.as_slice(), &attestation_reply_bytes)
        } else {
            if resp[0] == MSG_STATUS_MSG {
                let msg: StatusMsg = Deserialize::deserialize(&mut Deserializer::new(&resp[1..])).map_err(|e| e.to_string())?;
                Err(format!("Error getting device status: {}", msg.message))
            }
            else {
                Err("Invalid response message from device!".to_string())
            }
        }
    }

    fn ed25519_verify_signature(public_key_bytes: &[u8; 32], message: &[u8], signature_bytes: &[u8]) -> Result<(), String> {
        let pub_key = VerifyingKey::from_bytes(public_key_bytes).map_err(|e| e.to_string())?;
        let signature = Signature::try_from(signature_bytes).map_err(|e| e.to_string())?;

        pub_key.verify(message, &signature).map_err(|e| e.to_string())
    }
}