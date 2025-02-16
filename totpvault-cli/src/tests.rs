use crate::dev::TotpvaultDev;
#[cfg(test)]
mod tests {
    use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
    use rand_older::rngs::OsRng;
    use rmp_serde::to_vec;
    use totpvault_lib::{StatusMsg, MSG_STATUS_MSG};
    use crate::comm::check_status_msg;
    // Note this useful idiom: importing names from outer (for mod tests) scope.
    use super::*;

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
}