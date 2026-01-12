use esp_idf_svc::nvs::*;
use esp_idf_sys::{nvs_flash_erase, ESP_OK};

use crate::crypto::{decrypt_block, encrypt_block, AES_IV_LEN, AES_KEY_LEN};
use log::debug;
use totpvault_lib::MAX_SETTING_KEY_LEN;

const NVS_VAULT_NAMESPACE: &str = "vault";
const NVS_SETTINGS_NAMESPACE: &str = "settings";

pub fn format_nvs_partition() -> Result<(), String> {
    unsafe {
        let e = nvs_flash_erase();
        if e != ESP_OK {
            return Err("Unable to format default NVS partition!".to_string());
        }
    }
    Ok(())
}

fn get_nvs_handle(namespace: &str) -> Result<EspNvs<NvsDefault>, String> {
    let nvs_partition: EspNvsPartition<NvsDefault> = match EspDefaultNvsPartition::take() {
        Ok(v) => v,
        Err(_) => return Err("Unable to open default NVS partition".to_string()),
    };

    let nvs_h = match EspNvs::new(nvs_partition, namespace, true) {
        Ok(val) => val,
        Err(_) => return Err(format!("Unable to open NVS namespace {}!", namespace)),
    };

    Ok(nvs_h)
}

pub fn nvs_write_blob(key: &str, val: &[u8]) -> Result<(), String> {
    let mut nvs_h = get_nvs_handle(NVS_VAULT_NAMESPACE)?;

    match nvs_h.set_blob(key, val) {
        Ok(_) => Ok(()),
        Err(e) => Err(format!("Unable to set blob {}. ESP error = {}", key, e))
    }
}

pub fn nvs_write_setting(key: &str, val: &str) -> Result<(), String> {
    debug!("Writing setting: {} = {}", key, val);
    let mut nvs_h = get_nvs_handle(NVS_SETTINGS_NAMESPACE)?;
    match nvs_h.set_str(key, val) {
        Ok(_) => Ok(()),
        Err(e) => Err(format!("Unable to set setting {}. ESP error = {}", key, e))
    }
}

pub fn nvs_write_blob_encrypted(key: &str, val: &[u8], encryption_key: &[u8; AES_KEY_LEN]) -> Result<(), String> {
    let mut nvs_h = get_nvs_handle(NVS_VAULT_NAMESPACE)?;

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
    let nvs_h = get_nvs_handle(NVS_VAULT_NAMESPACE)?;

    let mut buf = [0_u8; 512];

    let nvs_read_result = nvs_h.get_blob(key, &mut buf).
        map_err(|e| format!("Unable to get blob {}. Database corrupted(?) please reset it. Error = {}", key, e))?;
    if let Some(val) = nvs_read_result {
       Ok(val.to_vec())
    } else {
        Err("Unable to read blob. Database corrupted(?) please reset it.".to_string())
    }
}

pub fn nvs_read_setting(key: &str) -> Result<String, String> {
    debug!("Reading setting: {}", key);
    let nvs_h = get_nvs_handle(NVS_SETTINGS_NAMESPACE)?;
    let mut buf = [0_u8; MAX_SETTING_KEY_LEN+1]; // Max setting value length (e.g., "yes", "no", etc.)
    match nvs_h.get_str(key, &mut buf) {
        Ok(Some(val)) => Ok(val.to_string()),
        Ok(None) => Err(format!("Setting '{}' not found.", key)),
        Err(e) => Err(format!("Error reading setting '{}': {}", key, e)),
    }
}

pub fn nvs_read_blob_encrypted(key: &str, encryption_key: &[u8; AES_KEY_LEN]) -> Result<Vec<u8>, String> {
    let nvs_h = get_nvs_handle(NVS_VAULT_NAMESPACE)?;
    let mut buf = [0_u8; 512]; // Note: Max expected size of encrypted blob

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
