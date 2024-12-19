const VID: &str = "1a86";
const PID: &str = "55d3";
use udev;

pub struct totpvault_dev {

}

impl totpvault_dev {
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

}