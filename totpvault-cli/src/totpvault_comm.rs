use std::fmt::Debug;
use std::io::Read;
use std::time::Duration;
use log::debug;
use rmp_serde::Serializer;
use serde::Serialize;
use serialport::SerialPort;
use totpvault_lib::{Message, StatusMsg, MSG_STATUS_MSG};

pub fn check_status_msg(resp: Vec<u8>) -> Result<(), String> {
    let resp_msg_type = resp[0];
    if resp_msg_type != MSG_STATUS_MSG {
        debug!("Expected a MSG_STATUS_MSG, but got type {} Raw = {:?}", resp_msg_type, resp);
        return Err(format!("Got unexpected message, type: {}", resp_msg_type));
    }

    let status_msg = rmp_serde::from_slice::<StatusMsg>(&resp[1..]).map_err(|e| format!("Error deserializing StatusMsg: {}", e))?;
    if status_msg.error {
        Err(status_msg.message)
    } else {
        Ok(())
    }
}

fn transmit_bytes(dev_path: &str, data: Vec<u8>) -> Result<Vec<u8>, String> {
    let mut resp = [0; 1024];
    let mut port = serialport::new(dev_path, 115_200)
        .timeout(Duration::from_millis(10000))
        .open().map_err(|e| format!("Unable to open serial port {}: {}", dev_path, e))?;

    // Before sending a message, clear read buffer
    empty_serial_buffer(&mut port, dev_path)?;

    port.write(&data).map_err(|e| format!("Error writing to serial port {}: {}", dev_path, e))?;

    port.read(&mut resp).map_err(|e| format!("Error reading from serial port {}: {}", dev_path, e))?;
    Ok(resp.to_vec())
}

pub fn send_command(dev_path: &str, command: u8) -> Result<Vec<u8>, String> {
    let data: Vec<u8> = vec![command];
    transmit_bytes(dev_path, data)
}


pub fn send_message<T: Serialize + Debug + Message>(dev_path: &str, message: T, command: u8) -> Result<Vec<u8>, String> {
    let mut data = vec![command];

    // Validate message structure
    if !message.validate() {
        return Err("Outbound message is not valid".to_string());
    }

    let mut buf: Vec<u8> = Vec::new();
    message.serialize(&mut Serializer::new(&mut buf)).map_err(|err| format!("Error serializing message: {}", err))?;

    // Append to the outgoing bytes buffer
    data.extend(buf);

    transmit_bytes(dev_path, data)
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