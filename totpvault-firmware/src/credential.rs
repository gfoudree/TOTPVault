use crate::{ crypto::{decrypt_block, encrypt_block, AES_IV_LEN, AES_KEY_LEN}, nvs_read_blob, nvs_write_blob};

use serde::{Deserialize, Serialize};
use totp_rs;
use zeroize::Zeroize;
use totpvault_lib;

pub const MAX_CREDENTIALS: u8 = 64;

#[derive(Serialize, Deserialize, Debug)]

pub struct Credential {
    // TODO: audit what would happen if an attacker can modify the plaintext fields
    pub domain_name: String,
    pub in_use: bool,
    pub slot_id: u8,
    #[serde(skip)]
    pub totp_secret_decrypted: Option<String>,
    pub totp_secret_encrypted: Vec<u8>,
    pub decryption_iv: [u8; AES_IV_LEN],
}

// Necessary for deserialization
impl Default for Credential {
    fn default() -> Self {
        Credential {
            domain_name: String::from(""),
            in_use: false,
            slot_id: 0,
            totp_secret_decrypted: None,
            totp_secret_encrypted: vec![],
            decryption_iv: [0; AES_IV_LEN],
        }
    }
}

impl Credential {
    pub fn gen_totp(cred: &Credential) -> Result<String, String> {
        if cred.in_use == false || cred.totp_secret_decrypted.is_none() {
            return Err("Invalid credential!".to_string());
        }

        let totp_encoded_secret = cred.totp_secret_decrypted.clone().unwrap();
        if totp_encoded_secret.len() < totpvault_lib::MIN_TOTP_SECRET_LEN || totp_encoded_secret.len() > totpvault_lib::MAX_TOTP_SECRET_LEN {
            return Err("Invalid credential!".to_string());
        }

        let totp = totp_rs::TOTP::new(totp_rs::Algorithm::SHA1, 6, 1, 30,
                                      totp_rs::Secret::Encoded(totp_encoded_secret).to_bytes().unwrap()).map_err(|e| format!("Error initializing TOTP: {}", e))?;

        let token = totp.generate_current().map_err(|e| format!("Error generating TOTP code: {}", e))?;
        Ok(token)
    }

    pub fn list_credentials(encryption_key: &[u8; AES_KEY_LEN]) -> Result<Vec<Credential>, String> {
        let mut creds: Vec<Credential> = Vec::new();
        for i in 0..MAX_CREDENTIALS {
            let cred = Self::get_credential(i, encryption_key)
                .map_err(|e| format!("Error listing credentials: {}", e))?;
            if cred.in_use {
                creds.push(cred);
            }
        }
        Ok(creds)
    }

    pub fn get_num_used_credentials(encryption_key: &[u8; AES_KEY_LEN]) -> Result<u8, String> {
        let mut used = 0;
        for i in 0..MAX_CREDENTIALS {
            let cred = Self::get_credential(i, encryption_key)
                .map_err(|e| format!("Error listing credentials: {}", e))?;
            if cred.in_use {
                used += 1;
            }
        }

        Ok(used)
    }
    
    pub fn get_credential(
        index: u8,
        encryption_key: &[u8; AES_KEY_LEN],
    ) -> Result<Credential, String> {
        let cred_serialized = nvs_read_blob(format!("slot{}", index).as_str())?;

        let mut cred: Credential = bincode::deserialize(&cred_serialized)
            .map_err(|e| format!("Error deserializing credential in slot {}. {}", index, e))?;

        // Check if credential is not in use and skip decryption since key will be invalid
        if cred.in_use == false {
            return Ok(cred);
        }

        // Decrypt credential since it is in use
        let plaintext = decrypt_block(
            &cred.totp_secret_encrypted.clone().to_vec(),
            encryption_key,
            &cred.decryption_iv,
        )
        .map_err(|e| format!("Error decrypting credential in slot {}. {}", index, e))?;

        #[cfg(debug_assertions)]
        println!("TOTP Secret: {:?}", plaintext);

        // TODO: check that this is valid
        cred.totp_secret_decrypted = Some(String::from_utf8(plaintext).map_err(|e| format!("Error with decrypted TOTP secret: {}", e))?);

        #[cfg(debug_assertions)]
        println!("Cred: {:?}", cred);

        Ok(cred)
    }

    pub fn init_credential(index: u8) -> Result<(), String> {
        let mut cred = Credential::default();
        cred.slot_id = index;
        cred.in_use = false;

        // Serialize it
        let binary_data = bincode::serialize(&cred)
            .map_err(|e| format!("Error serializing credential struct to binary! {}", e))?;

        nvs_write_blob(format!("slot{}", cred.slot_id).as_str(), &binary_data)?;

        Ok(())
    }

    fn find_open_slot(encryption_key: &[u8; AES_KEY_LEN]) -> Result<u8, String> {
        for i in 0..MAX_CREDENTIALS {
            if let Ok(cred) = Self::get_credential(i, encryption_key) {
                if cred.in_use == false {
                    return Ok(i);
                }
            }
        }
        Err("No available slots".to_string())
    }

    pub fn save_credential(
        cred: &mut Credential,
        encryption_key: &[u8; AES_KEY_LEN],
    ) -> Result<(), String> {
        // Names should be unique, check that none other exists
        if Self::credential_name_to_index(cred.domain_name.clone(), encryption_key).is_ok() {
            return Err("Credential name already in use!".to_string());
        }

        // Check if the credential is valid
        if cred.totp_secret_decrypted.is_none() {
            return Err("No secret to save!".to_string());
        }

        // Find an open slot for the credential
        cred.slot_id = Self::find_open_slot(encryption_key)?;

        // Encrypt TOTP secret
        let mut totp_secret = cred.totp_secret_decrypted.clone().unwrap();
        let (cipher_text, iv) = encrypt_block(totp_secret.as_bytes(), encryption_key)
            .map_err(|e| format!("Error encrypting TOTP secret! {}", e))?;

        totp_secret.zeroize();
        cred.totp_secret_encrypted = cipher_text;
        cred.decryption_iv = iv;

        // Serialize it
        let binary_data = bincode::serialize(&cred)
            .map_err(|e| format!("Error serializing credential struct to binary! {}", e))?;

        // Save it to NVS
        nvs_write_blob(format!("slot{}", cred.slot_id).as_str(), &binary_data)?;

        Ok(())
    }

    pub fn delete_credential(index: u8) -> Result<(), String> {
        // Doesn't matter if it's in use, just initialize it as a default
        Self::init_credential(index)?;
        Ok(())
    }

    pub fn credential_name_to_index(name: String, encryption_key: &[u8; AES_KEY_LEN]) -> Result<u8, String> {
        for i in 0..MAX_CREDENTIALS {
            if let Ok(cred) = Self::get_credential(i, encryption_key) {
                if cred.domain_name == name {
                    return Ok(i);
                }
            }
        }
        Err("Could not find the credential".to_string())
    }

    pub fn delete_credential_by_name(
        name: String,
        encryption_key: &[u8; AES_KEY_LEN],
    ) -> Result<(), String> {
        match Self::credential_name_to_index(name, encryption_key) {
            Ok(index) => {
                Credential::delete_credential(index)?;
                Ok(())
            },
            Err(e) => Err(e)
        }
    }

}
