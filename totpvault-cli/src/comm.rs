use log::debug;
use rmp_serde::Serializer;
use serde::Serialize;
use std::fmt::Debug;
use std::io::Read;
use std::time::Duration;
use totpvault_lib::{MSG_STATUS_MSG, Message, StatusMsg};

pub fn check_status_msg(resp: Vec<u8>) -> Result<(), String> {
    if resp.len() == 0 {
        return Err("Response length is 0!".to_string());
    }

    let resp_msg_type = resp[0];
    if resp_msg_type != MSG_STATUS_MSG {
        debug!(
            "Expected a MSG_STATUS_MSG, but got type {}\n Raw = {:?}\n Decoded (lossy) = {}",
            resp_msg_type,
            resp,
            String::from_utf8_lossy(&resp)
        );
        return Err(format!("Got unexpected message, type: {}", resp_msg_type));
    }

    let status_msg = rmp_serde::from_slice::<StatusMsg>(&resp[1..])
        .map_err(|e| format!("Error deserializing StatusMsg: {}", e))?;
    if status_msg.error {
        Err(status_msg.message)
    } else {
        Ok(())
    }
}

/// Read exactly `n` bytes from the port, blocking until all bytes arrive or the port times out.
fn read_exact(port: &mut Box<dyn serialport::SerialPort>, n: usize) -> Result<Vec<u8>, String> {
    let mut buf = vec![0u8; n];
    let mut total = 0;
    while total < n {
        match port.read(&mut buf[total..]) {
            Ok(0) => return Err("Serial port closed unexpectedly".to_string()),
            Ok(k) => total += k,
            Err(e) if e.kind() == std::io::ErrorKind::TimedOut => {
                return Err(format!(
                    "Timed out waiting for response from device (got {}/{} bytes)",
                    total, n
                ));
            }
            Err(e) => return Err(format!("Error reading from serial port: {}", e)),
        }
    }
    Ok(buf)
}

fn transmit_bytes(dev_path: &str, data: Vec<u8>, timeout_ms: u64) -> Result<Vec<u8>, String> {
    let mut port = serialport::new(dev_path, 115_200)
        .timeout(Duration::from_millis(timeout_ms))
        .open()
        .map_err(|e| format!("Unable to open serial port {}: {}", dev_path, e))?;

    // Drain any stale bytes that were left over from a previous (possibly interrupted) operation.
    // Only drain if there are actually bytes waiting — avoids blocking 100 ms on every call
    // when the buffer is already empty.
    let stale = port
        .bytes_to_read()
        .map_err(|e| format!("Unable to query serial port buffer: {}", e))?;
    if stale > 0 {
        port.set_timeout(Duration::from_millis(100))
            .map_err(|e| format!("Unable to set serial port timeout: {}", e))?;
        let mut drain_buf = [0u8; 4096];
        loop {
            match port.read(&mut drain_buf) {
                Ok(0) | Err(_) => break,
                Ok(_) => continue, // keep draining
            }
        }
    }

    // Restore the operation timeout for the actual request/response
    port.set_timeout(Duration::from_millis(timeout_ms))
        .map_err(|e| format!("Unable to set serial port timeout: {}", e))?;

    let written_bytes = port
        .write(&data)
        .map_err(|e| format!("Error writing to serial port {}: {}", dev_path, e))?;
    if written_bytes != data.len() {
        return Err("Could not write all the data to the serial port!".to_string());
    }

    // Read the 2-byte little-endian length prefix the firmware prepends to every response.
    let len_bytes = read_exact(&mut port, 2)?;
    let payload_len = u16::from_le_bytes([len_bytes[0], len_bytes[1]]) as usize;
    if payload_len == 0 || payload_len > 4096 {
        return Err(format!(
            "Implausible response length from device: {} bytes",
            payload_len
        ));
    }

    // Now read exactly that many bytes — no guessing, no sleeping.
    read_exact(&mut port, payload_len)
}

pub fn send_command(dev_path: &str, command: u8, timeout_ms: u64) -> Result<Vec<u8>, String> {
    let data: Vec<u8> = vec![command];
    transmit_bytes(dev_path, data, timeout_ms)
}

pub fn send_message<T: Serialize + Debug + Message>(
    dev_path: &str,
    message: T,
    command: u8,
    timeout_ms: u64,
) -> Result<Vec<u8>, String> {
    let mut data = vec![command];

    // Validate message structure
    if !message.validate() {
        return Err(
            "Command is not valid! Re-run with '-v' to see verbose information".to_string(),
        );
    }

    let mut buf: Vec<u8> = Vec::new();
    message
        .serialize(&mut Serializer::new(&mut buf))
        .map_err(|err| format!("Error serializing message: {}", err))?;

    // Append to the outgoing bytes buffer
    data.extend(buf);

    transmit_bytes(dev_path, data, timeout_ms)
}
