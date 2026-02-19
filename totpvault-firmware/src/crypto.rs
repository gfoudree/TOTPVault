use aes_gcm::aead::{Aead, KeyInit, OsRng}; // Traits for key generation and random number generation
use aes_gcm::{Aes256Gcm, Error, Key, Nonce};
use rand::RngCore;
use base64::prelude::*;
use ed25519_dalek::{Signature, Signer, SigningKey, SECRET_KEY_LENGTH};
use crate::{storage, NONCE_CHALLENGE_LEN, NVS_KEY_ED25519, SALT_LEN};

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

fn get_ed25519_private_key_nvs(nvs_storage: &mut storage::Storage) -> Result<SigningKey, String> {
    let private_key_bytes = nvs_storage.nvs_read_blob(NVS_KEY_ED25519)?;
    let r: [u8; SECRET_KEY_LENGTH] = private_key_bytes.try_into().map_err(|_|format!("Unable to decode stored private key into ED25519 private key"))?;

    // Key is zeroized on drop if the zeroize crate feature is enabled for ed25519-dalek
    Ok(SigningKey::from_bytes(&r))
}

pub fn sign_challenge(challenge: &[u8; NONCE_CHALLENGE_LEN], nvs_storage: &mut storage::Storage) -> Result<Signature, String> {
    let pkey = get_ed25519_private_key_nvs(nvs_storage)?;
    let signature = pkey.sign(challenge);

    Ok(signature)
}

pub fn get_ed25519_public_key_nvs(nvs_storage: &mut storage::Storage) -> Result<String, String> {
    let pkey = get_ed25519_private_key_nvs(nvs_storage)?;
    let pubkey = pkey.verifying_key();
    
    // Convert it into a string
    let encoded = BASE64_STANDARD.encode(pubkey.as_bytes());
    #[cfg(debug_assertions)]
    {
        println!("Public key (raw): {:?}", pubkey.as_bytes());
        println!("Public key (encoded): {:02X?}", encoded);
    }
    Ok(encoded)
}

pub fn gen_salt() -> [u8; SALT_LEN] {
    let mut buffer = [0u8; SALT_LEN]; // Create a buffer of SALT_LEN
    let mut rng = OsRng; // Create a new instance of OsRng

    rng.fill_bytes(&mut buffer); // Verified via radare to call esp_fill_random()
    buffer
}

pub fn gen_ed25519_keypair() -> SigningKey {
    let mut rng = OsRng;
    let key: SigningKey = SigningKey::generate(&mut rng);

    key
}