#[cfg(test)]
mod tests {
    use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
    use rand_older::{rngs::OsRng};
    use rmp_serde::to_vec;
    use totp_rs::{Secret, TOTP};
    use totpvault_lib::{CreateEntryMsg, Message, StatusMsg, MAX_PW_LEN, MSG_STATUS_MSG};
    use crate::{comm::check_status_msg, dev::TotpvaultDev};

    fn init_vault(dev: &String) {
        let valid_pw = "password12345!";
        TotpvaultDev::init_vault(&dev, valid_pw).unwrap();
    }
    fn unlock_vault(dev: &String) {
        let valid_pw = "password12345!";
        TotpvaultDev::unlock_vault(&dev, valid_pw).unwrap();
    }
    
    #[test]
    fn test_public_key_to_hash_invalid_base64() {
        let invalid_public_key = "!!invalid_base64!!";
        assert!(TotpvaultDev::public_key_to_hash(invalid_public_key).is_err());
    }

    #[test]
    fn test_public_key_to_hash_empty_input() {
        let empty_key = "";
        assert!(TotpvaultDev::public_key_to_hash(empty_key).is_err());
    }
    #[test]
    fn test_public_key_to_hash_valid_input() {
        let valid_key = "U29tZVZhbGlkUHVibGljS2V5";
        assert!(TotpvaultDev::public_key_to_hash(valid_key).is_ok());
    }

    #[test]
    fn test_valid_signature() {
        // Generate a signing key
        let mut csprng = OsRng;
        let signing_key = SigningKey::generate(&mut csprng);
        let verifying_key = VerifyingKey::from(&signing_key);

        let message = b"Hello, world!";
        let signature: Signature = signing_key.sign(message);

        // Verify the signature
        let result = TotpvaultDev::ed25519_verify_signature(
            verifying_key.as_bytes(),
            message,
            &signature.to_vec(),
        );

        assert!(result.is_ok());
    }

    #[test]
    fn test_invalid_signature() {
        let mut csprng = OsRng;
        let signing_key = SigningKey::generate(&mut csprng);
        let verifying_key = VerifyingKey::from(&signing_key);

        let message = b"Hello, world!";
        let signature: Signature = signing_key.sign(message);

        // Tampered message
        let tampered_message = b"Hello, rust!";

        let result = TotpvaultDev::ed25519_verify_signature(
            verifying_key.as_bytes(),
            tampered_message,
            &signature.to_vec(),
        );

        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_public_key() {
        let mut csprng = OsRng;
        let signing_key = SigningKey::generate(&mut csprng);

        let message = b"Hello, world!";
        let signature: Signature = signing_key.sign(message);

        // Generate a different keypair
        let different_signing_key = SigningKey::generate(&mut csprng);
        let different_verifying_key = VerifyingKey::from(&different_signing_key);

        let result = TotpvaultDev::ed25519_verify_signature(
            different_verifying_key.as_bytes(),
            message,
            &signature.to_vec(),
        );

        assert!(result.is_err());
    }

    #[test]
    fn test_empty_fields() {
        let empty_field = [0u8; 32];
        let mut csprng = OsRng;
        let signing_key = SigningKey::generate(&mut csprng);
        let verifying_key = VerifyingKey::from(&signing_key);

        let message = b"Hello, world!";
        let signature: Signature = signing_key.sign(message);

        assert!(TotpvaultDev::ed25519_verify_signature( verifying_key.as_bytes(),
                                                        &empty_field,
                                                        &signature.to_vec()).is_err());
        assert!(TotpvaultDev::ed25519_verify_signature( &empty_field,
                                                        message,
                                                        &signature.to_vec()).is_err());
        assert!(TotpvaultDev::ed25519_verify_signature( verifying_key.as_bytes(),
                                                        message,
                                                        &empty_field).is_err());
    }

    #[test]
    fn test_valid_success_status_msg() {
        let status_msg = StatusMsg {
            error: false,
            message: "Operation successful".to_string(),
        };
        let mut encoded = vec![MSG_STATUS_MSG];
        encoded.extend(to_vec(&status_msg).unwrap());

        let result = check_status_msg(encoded);
        assert!(result.is_ok());
    }

    #[test]
    fn test_valid_error_status_msg() {
        let status_msg = StatusMsg {
            error: true,
            message: "Something went wrong".to_string(),
        };
        let mut encoded = vec![MSG_STATUS_MSG];
        encoded.extend(to_vec(&status_msg).unwrap());

        let result = check_status_msg(encoded);
        assert_eq!(result, Err("Something went wrong".to_string()));
    }

    #[test]
    fn test_invalid_message_type() {
        let invalid_type = 2; // Some other message type
        let status_msg = StatusMsg {
            error: false,
            message: "This should be ignored".to_string(),
        };
        let mut encoded = vec![invalid_type];
        encoded.extend(to_vec(&status_msg).unwrap());

        let result = check_status_msg(encoded);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Got unexpected message, type: 2"));
    }

    #[test]
    fn test_malformed_message() {
        let mut invalid_data = vec![MSG_STATUS_MSG];
        invalid_data.extend(vec![0, 1, 2, 3, 4]); // Corrupt data

        let result = check_status_msg(invalid_data);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Error deserializing StatusMsg"));
    }

    #[test]
    fn test_empty_message() {
        let result = check_status_msg(vec![]);
        assert!(result.is_err()); // Should fail due to missing type byte
    }

    #[test]
    fn test_message_with_only_type_byte() {
        let result = check_status_msg(vec![MSG_STATUS_MSG]);
        assert!(result.is_err()); // Should fail due to missing payload
    }

    // Hardware tests
    #[test]
    fn test_hw_init_vault() {
        let valid_totp_secret = "HVR4CFHAFOWFGGFAGSA5JVTIMMPG6GMT";
        let dev = TotpvaultDev::find_device().unwrap();

        // Test with invalid password
        assert!(TotpvaultDev::init_vault(&dev, "pass").is_err());
        assert!(TotpvaultDev::init_vault(&dev, "").is_err());
        assert!(TotpvaultDev::init_vault(&dev, "a".repeat(MAX_PW_LEN+10).as_str()).is_err());

        // Create with valid password
        init_vault(&dev);

        // Check that all options are blocked when the vault is locked
        assert!(TotpvaultDev::list_stored_credentials(&dev).is_err());
        assert!(TotpvaultDev::add_credential(&dev, "google.com", valid_totp_secret).is_err());
        assert!(TotpvaultDev::sync_time(&dev).is_err());
        assert!(TotpvaultDev::delete_credential(&dev, "google.com").is_err());
        assert!(TotpvaultDev::get_totp_code(&dev, "google.com").is_err());

        // Check that specific options are allowed even if it's locked: Status

            let mut status = TotpvaultDev::get_device_status(&dev).unwrap();
            assert_eq!(status.vault_unlocked, false);

            // Check that slot usage is correct after formatting (used/free is hidden if locked)
            assert_eq!(status.used_slots, 0);
            assert_eq!(status.free_slots, 0);
            assert_eq!(status.total_slots, 64);
            assert!(status.public_key.len() > 16);
            assert!(status.version_str.contains("Version"));
            assert!(status.current_timestamp > 1);


        // Unlock vault
        assert!(TotpvaultDev::unlock_vault(&dev, "pass").is_err());
        assert!(TotpvaultDev::unlock_vault(&dev, "").is_err());
        assert!(TotpvaultDev::unlock_vault(&dev, "\x00").is_err());
        assert!(TotpvaultDev::unlock_vault(&dev, "a".repeat(MAX_PW_LEN+10).as_str()).is_err());
        

        status = TotpvaultDev::get_device_status(&dev).unwrap();
            assert_eq!(status.vault_unlocked, true);
            assert_eq!(status.used_slots, 0);
            assert_eq!(status.free_slots, 64);
            assert_eq!(status.total_slots, status.free_slots);
            assert!(status.public_key.len() > 16);
            assert!(status.version_str.contains("Version"));
            assert!(status.current_timestamp > 1);


        // Test lock -> unlock
        assert!(TotpvaultDev::lock_vault(&dev).is_ok());
         status = TotpvaultDev::get_device_status(&dev).unwrap();
            assert_eq!(status.vault_unlocked, false);

        unlock_vault(&dev);

        status = TotpvaultDev::get_device_status(&dev).unwrap();
            assert_eq!(status.vault_unlocked, true);

        // Sync time
        assert!(TotpvaultDev::sync_time(&dev).is_ok());

        // Test creating invalid items
        assert!(TotpvaultDev::list_stored_credentials(&dev).unwrap().is_empty());
        assert!(TotpvaultDev::add_credential(&dev, "g", valid_totp_secret).is_err());
        assert!(TotpvaultDev::add_credential(&dev, "g".repeat(512).as_str(), valid_totp_secret).is_err());
        assert!(TotpvaultDev::add_credential(&dev, "", valid_totp_secret).is_err());
        assert!(TotpvaultDev::add_credential(&dev, "google.com", "").is_err());
        assert!(TotpvaultDev::add_credential(&dev, "google.com", "a".repeat(512).as_str()).is_err());
        assert!(TotpvaultDev::list_stored_credentials(&dev).unwrap().is_empty());

        // TODO: Test deleting entries

        // TODO: Check adding duplicate entry

        // TODO: Generate TOTP code for non-existent entry
        // TODO: Delete non-existent entry

        // Make valid items
        for i in 0..64 {
            let domain = format!("test{}.com", i as u8);
            println!("{}", domain);
            TotpvaultDev::add_credential(&dev, domain.as_str(), valid_totp_secret).unwrap();
            let creds = TotpvaultDev::list_stored_credentials(&dev).unwrap();
            assert_eq!(creds.len(), i + 1);
            status = TotpvaultDev::get_device_status(&dev).unwrap();
            assert_eq!(status.used_slots, i as u8 + 1);
            assert_eq!(status.free_slots, 64 - (i as u8 + 1));
        }

        // Now the device is full, make sure adding an item fails
        assert!(TotpvaultDev::add_credential(&dev, "test_too_full.com", valid_totp_secret).is_err());
    }

    #[test]
    fn test_totp_validation_algorithm() {
        for _ in  0..2048 {
            let secret = Secret::generate_secret();
            let b32_encoded_secret = secret.to_encoded().to_string();

            let create_msg = CreateEntryMsg{domain_name: "google.com".to_string(), totp_secret: b32_encoded_secret};
            assert!(create_msg.validate() == true);
        }
    }
    
    #[test]
    fn test_hw_totp_code() {
        let dev = TotpvaultDev::find_device().unwrap();
        init_vault(&dev);
        unlock_vault(&dev);
        // Sync time
        assert!(TotpvaultDev::sync_time(&dev).is_ok());

        assert!(TotpvaultDev::list_stored_credentials(&dev).unwrap().is_empty());
        for i in 0..5 {
            let secret = Secret::generate_secret();
            let b32_encoded_secret = secret.to_encoded().to_string();
            let domain_name = format!("test{}.com", i);

            // Add it to the vault
            assert!(TotpvaultDev::add_credential(&dev, domain_name.as_str(), b32_encoded_secret.as_str()).is_ok());

            // Retrieve TOTP code from the hardware device
            let retrieved_totp_code = TotpvaultDev::get_totp_code(&dev, domain_name.as_str()).unwrap();
            let totp = TOTP::new(totp_rs::Algorithm::SHA1, 6, 1, 30, secret.to_bytes().unwrap()).unwrap();

            // Compare the TOTP codes
            assert_eq!(totp.generate_current().unwrap(), retrieved_totp_code);
        }
    }
}