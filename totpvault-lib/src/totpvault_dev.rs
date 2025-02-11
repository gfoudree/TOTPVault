const VID: u16 = 0x1a86;
const PID: u16 = 0x55d3;

use std::{env, vec};
use std::fmt::Debug;
use rmp_serde::{Deserializer, Serializer};
use serialport;
use std::time::Duration;
use serde::{Deserialize, Serialize};
use std::io::Cursor;
use chrono::Utc;
use log::{debug, error, info};
use serialport::{SerialPort, SerialPortType};

use crate::*;
pub struct TotpvaultDev {

}

impl TotpvaultDev {
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
                                        info!("Using USB device {:02x}:{:02x} @ {}", info.vid, info.pid, port.port_name);
                                        return Ok(port.port_name);
                                    }
                                    "macos" => {
                                        if port.port_name.contains("tty") {
                                            info!("Using USB device {:02x}:{:02x} @ {}", info.vid, info.pid, port.port_name);
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

    fn empty_serial_buffer(port: &mut Box<dyn SerialPort>, dev_path: &str) -> Result<(), String> {
        let mut resp = [0; 1024];
        let mut avail_bytes = port.bytes_to_read().map_err(|e| format!("Unable to check available bytes on serial port {}: {}", dev_path, e))?;
        while avail_bytes > 0 {
            port.read(&mut resp).map_err(|e| format!("Error reading from serial port {}: {}", dev_path, e))?;
            std::thread::sleep(Duration::from_millis(500));
            avail_bytes = port.bytes_to_read().map_err(|e| format!("Unable to check available bytes on serial port {}: {}", dev_path, e))?;
        }

        Ok(())
    }

    fn send_message_verify<T: Serialize + Debug>(dev_path: &str, message: T, command: u8) -> Result<(), String> {
        let mut buf: Vec<u8> = Vec::new();
        message.serialize(&mut Serializer::new(&mut buf)).unwrap();
        let resp = Self::send_message(dev_path, command, Some(buf))?;
        if String::from_utf8_lossy(resp.as_slice()).contains("Success") {
            Ok(())
        } else {
            debug!("Failed to send command={} with message={:?}. Got: {:?}", command, message, resp);
            Err("Failed to send command".to_string())
        }
    }

    pub fn send_message(dev_path: &str, command: u8, message: Option<Vec<u8>>) -> Result<Vec<u8>, String> {
        let mut data: Vec<u8> = Vec::new();
        let mut resp = [0; 1024];

        // Build message stream
        data.push(command);
        if message.is_some() {
            data.extend(message.unwrap());
        }

        let mut port = serialport::new(dev_path, 115_200)
            .timeout(Duration::from_millis(1000))
            .open().map_err(|e| format!("Unable to open serial port {}: {}", dev_path, e))?;

        // Before sending a message, clear read buffer
        Self::empty_serial_buffer(&mut port, dev_path)?;

        port.write(&data).map_err(|e| format!("Error writing to serial port {}: {}", dev_path, e))?;

        port.read(&mut resp).map_err(|e| format!("Error reading from serial port {}: {}", dev_path, e))?;
        Ok(resp.to_vec())
    }

    pub fn get_device_status(dev_path: &str) -> Result<SystemInfoMsg, String> {
        let resp = Self::send_message(dev_path, CMD_DEV_INFO, None)?;
        // Check that we got a valid SYSINFO message
        if resp[0] != MSG_SYSINFO {
            // Dump error out
            if resp[0] == MSG_STATUS_MSG {
                let msg: StatusMsg = Deserialize::deserialize(&mut Deserializer::new(&resp[1..])).map_err(|e| e.to_string())?;
                error!("Error getting device status: {}", msg.message);
            }
            return Err("Invalid response message from device!".to_string());
        }
        let mut cursor_buf = Cursor::new(resp[1..].to_vec());
        let msg: SystemInfoMsg = Deserialize::deserialize(&mut Deserializer::new(& mut cursor_buf)).map_err(|e| e.to_string())?;

        Ok(msg)
    }
    
    pub fn list_stored_credentials(dev_path: &str) -> Result<Vec<CredentialInfo>, String> {
        // TODO: complete
        Ok(vec![CredentialInfo{ domain_name: "google.com".to_string(), slot_id: 0 }])
    }
    
    pub fn get_totp_code(dev_path: &str, credential: &CredentialInfo) -> Result<String, String> {
        // TODO: complete. Change in Firmware to display the TOTP code with the listing of credentials to reduce time
        Ok("12345".to_string())
    }
    
    pub fn add_credential(dev_path: &str, domain_name: &str, totp_secret: &str) -> Result<(), String> {
        match Self::send_message_verify(dev_path, CreateEntryMsg{domain_name: domain_name.to_string(), totp_secret: totp_secret.to_string()}, CMD_CREATE) {
            Ok(_) => Ok(()),
            Err(_) => Err("Failed to create credential! Check logs".to_string())
        }
    }
    pub fn delete_credential(dev_path: &str, domain_name: &str) -> Result<(), String> {
        match Self::send_message_verify(dev_path, DeleteEntryMsg{domain_name: domain_name.to_string()}, CMD_DELETE) {
            Ok(_) => Ok(()),
            Err(_) => Err("Failed to delete credential! Check logs".to_string())
        }
    }

    pub fn unlock_vault(dev_path: &str, password: &str) -> Result<(), String> {
        match Self::send_message_verify(dev_path, UnlockMsg{password: password.to_string()}, CMD_UNLOCK_VAULT) {
            Ok(_) => Ok(()),
            Err(_) => Err("Failed to unlock the vault! Check logs".to_string())
        }
    }

    pub fn init_vault(dev_path: &str, password: &str) -> Result<(), String> {
        match Self::send_message_verify(dev_path, InitVaultMsg{password: password.to_string()}, CMD_INIT_VAULT) {
            Ok(_) => Ok(()),
            Err(_) => Err("Vault failed to initialize! Check logs".to_string())
        }
    }
    pub fn sync_time(dev_path: &str) -> Result<(), String> {
        match Self::send_message_verify(dev_path, SetTimeMsg{unix_timestamp: Utc::now().timestamp() as u64}, CMD_SET_TIME) {
            Ok(_) => Ok(()),
            Err(_) => Err("Failed to sync time! Check logs".to_string())
        }
    }
}