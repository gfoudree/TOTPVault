const VID: &str = "1a86";
const PID: &str = "55d3";
use udev;
use rmp_serde::{Deserializer, Serializer};
use serialport;
use std::time::Duration;
use serde::{Serialize, Deserialize};
use totpvault_lib::*;
use std::io::Cursor;

pub struct TotpvaultDev {

}

impl TotpvaultDev {
    pub fn find_device() -> Result<String, String> {
        let mut enumerator = udev::Enumerator::new().unwrap();
        enumerator.match_subsystem("tty").unwrap();
        for device in enumerator.scan_devices().unwrap() {
            let mut vid_match = false;
            let mut pid_match = false;

            for property in device.properties() {
                if property.name().to_str().unwrap().contains("ID_USB_VENDOR_ID") && property.value().to_str().unwrap().contains(VID) {
                    vid_match = true;
                } else if property.name().to_str().unwrap().contains("ID_USB_MODEL_ID") && property.value().to_str().unwrap().contains(PID) {
                    pid_match = true;
                }
            }
            if vid_match && pid_match {
                return Ok(device.devnode().unwrap().to_str().unwrap().to_string());
            }
        }
        Err("No TOTPVault devices found!".to_string())
    }

    pub fn get_device_status(dev_path: &str) -> Result<SystemInfoMsg, String> {
        // TODO: clean this monster mess up...
        let msg = vec![CMD_DEV_INFO];

        let mut port = serialport::new(dev_path, 115_200)
            .timeout(Duration::from_millis(1000))
            .open().map_err(|e| format!("Unable to open serial port {}: {}", dev_path, e))?;

        port.write(&msg).map_err(|e| format!("Error writing to serial port {}: {}", dev_path, e))?;
        let mut resp = [0; 128];

        port.read(&mut resp).map_err(|e| format!("Error reading from serial port {}: {}", dev_path, e))?;

        // Check that we got a valid SYSINFO message
        if resp[0] != MSG_SYSINFO {
            return Err("Invalid response message from device!".to_string());
        }
        let mut de = Cursor::new(resp[1..].to_vec());
        let msg: SystemInfoMsg = Deserialize::deserialize(&mut Deserializer::new(& mut de)).map_err(|e| e.to_string())?;
        Ok(msg)
    }
}