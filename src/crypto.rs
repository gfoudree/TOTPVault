use aes_gcm::aead::{Aead, KeyInit, OsRng}; // Traits for key generation and random number generation
use aes_gcm::{Aes256Gcm, Error, Key, Nonce};
use rand::RngCore;
use ed25519_dalek::{Signature, Signer, SigningKey, PUBLIC_KEY_LENGTH, SECRET_KEY_LENGTH};
use crate::{nvs_read_blob, NONCE_CHALLENGE_LEN, NVS_KEY_ED25519};

pub const AES_IV_LEN: usize = 12;
pub const AES_KEY_LEN: usize = 256 / 8;

pub fn encrypt_block(
    data: &[u8],
    encryption_key: &[u8; AES_KEY_LEN],
) -> Result<(Vec<u8>, [u8; AES_IV_LEN]), Error> {
    // Encrypt value
    let mut rng = [0u8; AES_IV_LEN];
    OsRng.fill_bytes(&mut rng);

    let nonce = Nonce::from_slice(&rng);

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(encryption_key));

    match cipher.encrypt(nonce, data) {
        Ok(cipher_text) => {
            #[cfg(debug_assertions)]
            {
                println!("Encrypting {:02X?}", data);
                println!("Nonce: {:02X?}", nonce);
                println!("Key: {:02X?}", encryption_key);
                println!("Encrypted: {:02X?}\n\n\n", cipher_text);
            }

            Ok((cipher_text, rng))
        }
        Err(e) => Err(e),
    }
}

pub fn decrypt_block(
    cipher_text: &[u8],
    encryption_key: &[u8; AES_KEY_LEN],
    iv: &[u8],
) -> Result<Vec<u8>, Error> {
    // Decrypt
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(encryption_key));
    let nonce = Nonce::from_slice(iv);

    #[cfg(debug_assertions)]
    {
        println!("Ciphertext: {:02X?}", cipher_text);
        println!("Nonce: {:02X?}", nonce);
        println!("Key: {:02X?}", encryption_key);
    }
    cipher.decrypt(nonce, cipher_text)
}

fn get_ed25519_privkey() -> Result<SigningKey, String> {
    let private_key_bytes = nvs_read_blob(NVS_KEY_ED25519)?;
    let r: [u8; SECRET_KEY_LENGTH] = private_key_bytes.try_into().map_err(|_|format!("Unable to decode stored private key into ED25519 private key"))?;

    // Key is zeroized on drop if the zeroize crate feature is enabled for ed25519-dalek
    Ok(SigningKey::from_bytes(&r))
}

pub fn sign_challenge(challenge: &[u8; NONCE_CHALLENGE_LEN]) -> Result<Signature, String> {
    let pkey = get_ed25519_privkey()?;
    let signature = pkey.sign(challenge);

    Ok(signature)
}

pub fn get_pubkey() -> Result<String, String> {
    let pkey = get_ed25519_privkey()?;
    let pubkey = pkey.verifying_key();
    
    // Convert it into a string
    let encoded = base64::encode(pubkey.as_bytes());
    //let pubkey_hex = pubkey.as_bytes().iter().map(|e| format!("{:02X}", e)).collect::<Vec<String>>().join("");
    Ok(encoded)
}