use esp_idf_svc::nvs::*;
use esp_idf_sys::{nvs_flash_erase, ESP_OK};

use crate::crypto::{decrypt_block, encrypt_block, AES_IV_LEN, AES_KEY_LEN};

const NVS_VAULT_NAMESPACE: &str = "vault";

pub fn format_nvs_partition() -> Result<(), String> {
    unsafe {
        let e = nvs_flash_erase();
        if e != ESP_OK {
            return Err("Unable to format default NVS partition!".to_string());
        }
    }
    Ok(())
    
}
fn get_nvs_handle() -> Result<EspNvs<NvsDefault>, String> {
    let nvs_partition: EspNvsPartition<NvsDefault> = match EspDefaultNvsPartition::take() {
        Ok(v) => v,
        Err(_) => return Err("Unable to open default NVS partition".to_string()),
    };

    let nvs_h = match EspNvs::new(nvs_partition, NVS_VAULT_NAMESPACE, true) {
        Ok(val) => val,
        Err(_) => return Err("Unable to open NVS partition!".to_string()),
    };

    Ok(nvs_h)
}



pub fn nvs_write_u8(key: &str, val: u8) -> Result<(), String> {
    let nvs_h = get_nvs_handle()?;

    match nvs_h.set_u8(key, val) {
        Ok(_) => return Ok(()),
        Err(e) => return Err(format!("Unable to set u8 {}. ESP error = {}", key, e))
    }
}

pub fn nvs_read_u8(key: &str) -> Result<u8, String> {
    let nvs_h = get_nvs_handle()?;

    let val = match nvs_h.get_u8(key) {
        Ok(Some(val)) => val,
        Err(e) => {
            return Err(format!(
                "Unable to access blob. Database corrupted(?) please reset it. Err: {}",
                e
            ));
        }
        Ok(None) => {
            return Err(
                "Unable to access blob. Database corrupted(?) please reset it."
                    .to_string(),
            );
        }
    };

    Ok(val)
}


pub fn nvs_write_blob(key: &str, val: &[u8]) -> Result<(), String> {
    let mut nvs_h = get_nvs_handle()?;

    match nvs_h.set_blob(key, val) {
        Ok(_) => return Ok(()),
        Err(e) => return Err(format!("Unable to set blob {}. ESP error = {}", key, e))
    };
}

pub fn nvs_write_blob_encrypted(key: &str, val: &[u8], encryption_key: &[u8; AES_KEY_LEN]) -> Result<(), String> {
    let mut nvs_h = get_nvs_handle()?;

    match encrypt_block(val, encryption_key) {
        Ok((cipher_text, iv)) => {
            // Store data as IV + ciphertext
            let mut buf = iv.to_vec();
            buf.extend(cipher_text);

            match nvs_h.set_blob(key, &buf) {
                Ok(_) => return Ok(()),
                Err(e) => return Err(format!("Unable to set blob {}. ESP error = {}", key, e))
            };
        },
        Err(e) => return Err(format!("Unable to encrypt blob {}. Encryption error = {}", key, e))
    }
    
}

pub fn nvs_read_blob(key: &str) -> Result<Vec<u8>, String> {
    let nvs_h = get_nvs_handle()?;

    let mut buf = [0_u8; 512];

    let nvs_read_result = nvs_h.get_blob(key, &mut buf).
        map_err(|e| format!("Unable to get blob {}. Database corrupted(?) please reset it. Error = {}", key, e))?;
    if let Some(val) = nvs_read_result {
       Ok(val.to_vec())
    } else {
        Err("Unable to read blob. Database corrupted(?) please reset it.".to_string())
    }
}

pub fn nvs_read_blob_encrypted(key: &str, encryption_key: &[u8; AES_KEY_LEN]) -> Result<Vec<u8>, String> {
    let nvs_h = get_nvs_handle()?;

    let mut buf = [0_u8; 512];

    let nvs_read_result = nvs_h.get_blob(key, &mut buf).
        map_err(|e| format!("Unable to get blob {}. Database corrupted(?) please reset it. Error = {}", key, e))?;
    if let Some(val) = nvs_read_result {
        // Separate IV from ciphertext
        let iv = &val[0..AES_IV_LEN];
        let ciphertext = &val[AES_IV_LEN..];

        let plaintext = match decrypt_block( ciphertext, encryption_key, iv) {
            Ok(v) => v,
            Err(e) => { return Err(format!("Error decrypting blob! {}", e)); }
        };

        Ok(plaintext)
    } else {
        Err("Unable to read blob. Database corrupted(?) please reset it.".to_string())
    }
}