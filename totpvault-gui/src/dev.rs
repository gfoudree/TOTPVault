const VID: u16 = 0x1a86;
const PID: u16 = 0x55d3;

use std::env;
use rmp_serde::{Deserializer, Serializer};
use serialport;
use std::time::Duration;
use serde::{Serialize, Deserialize};
use totpvault_lib::*;
use std::io::Cursor;
use log::{debug, error, info};
use serialport::{SerialPort, SerialPortType};

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

    pub fn send_message(dev_path: &str, msg: u8) -> Result<Vec<u8>, String> {
        let msg = vec![msg];
        let mut resp = [0; 1024];

        let mut port = serialport::new(dev_path, 115_200)
            .timeout(Duration::from_millis(1000))
            .open().map_err(|e| format!("Unable to open serial port {}: {}", dev_path, e))?;

        // Before sending a message, clear read buffer
        Self::empty_serial_buffer(&mut port, dev_path)?;

        port.write(&msg).map_err(|e| format!("Error writing to serial port {}: {}", dev_path, e))?;

        port.read(&mut resp).map_err(|e| format!("Error reading from serial port {}: {}", dev_path, e))?;
        Ok(resp.to_vec())
    }

    pub fn get_device_status(dev_path: &str) -> Result<SystemInfoMsg, String> {
        let resp = Self::send_message(dev_path, CMD_DEV_INFO)?;
        // Check that we got a valid SYSINFO message
        // TODO: cleanup code calling to always check for errors in a generic function
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
}