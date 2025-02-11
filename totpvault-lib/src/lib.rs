pub mod totpvault_dev;

use data_encoding::BASE32;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

pub const CMD_SET_TIME: u8 = 0x10;
pub const CMD_CREATE: u8 = 0x11;
pub const CMD_LIST: u8 = 0x12;
pub const CMD_DELETE: u8 = 0x13;
pub const CMD_DISPLAY_CODE: u8 = 0x14;
pub const CMD_DEV_INFO: u8 = 0x15;
pub const CMD_UNLOCK_VAULT: u8 = 0x1A;
pub const CMD_INIT_VAULT: u8 = 0x1B;
pub const CMD_ATTEST: u8 = 0x1C;
pub const CMD_LOCK_VAULT: u8 = 0x1E;
pub const MSG_STATUS_MSG: u8 = 0x01;
pub const MSG_SYSINFO: u8 = 0x20;
pub const MSG_ATTESTATION_RESPONSE: u8 = 0x21;
pub const MSG_LIST_CREDS: u8 = 0x22;
pub const MSG_TOTP_CODE: u8 = 0x23;

pub const MIN_TOTP_SECRET_LEN: usize = 16;
pub const MAX_TOTP_SECRET_LEN: usize = 64;
pub const MAX_DOMAIN_LEN: usize = 64;
pub const MIN_DOMAIN_LEN: usize = 2;
pub const MIN_PW_LEN: usize = 12;
pub const MAX_PW_LEN: usize = 128;
const MIN_TIMESTAMP: u64 = 1728590640;
pub const NONCE_CHALLENGE_LEN: usize = 64;

pub const SUCCESS_MSG: &str = "Success!";

pub trait Message {
    fn validate(&self) -> bool;
    fn message_type_byte(&self) -> u8;
}

#[derive(Serialize, Deserialize, Debug, Zeroize, ZeroizeOnDrop)]
pub struct CreateEntryMsg {
    pub domain_name: String,
    pub totp_secret: String,
}

#[derive(Serialize, Deserialize, Debug, Zeroize, ZeroizeOnDrop)]
pub struct UnlockMsg {
    pub password: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SetTimeMsg {
    pub unix_timestamp: u64,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct DeleteEntryMsg {
    pub domain_name: String,
}

#[derive(Serialize, Deserialize, Debug, Zeroize, ZeroizeOnDrop)]
pub struct InitVaultMsg {
    pub password: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct DisplayCodeMsg {
    pub domain_name: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct AuthenticateChallengeMsg {
    pub nonce_challenge: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct CredentialInfo {
    pub domain_name: String,
    pub slot_id: u8,
}
#[derive(Serialize, Deserialize, Debug)]
pub struct CredentialListMsg {
    pub credentials: Vec<CredentialInfo>,
}
#[derive(Serialize, Deserialize, Debug)]
pub struct TOTPCodeMsg {
    pub totp_code: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SystemInfoMsg {
    pub total_slots: u8,
    pub used_slots: u8,
    pub free_slots: u8,
    pub current_timestamp: u64,
    pub version_str: String,
    pub vault_unlocked: bool,
    pub public_key: String, // Base64 encoded
}
#[derive(Serialize, Deserialize, Debug)]
pub struct StatusMsg {
    pub error: bool,
    pub message: String,
}
#[derive(Serialize, Deserialize, Debug)]
pub struct AttestationResponseMsg {
    pub message: String,
}

impl Message for TOTPCodeMsg {
    fn validate(&self) -> bool { true }
    fn message_type_byte(&self) -> u8 { MSG_TOTP_CODE }
}
impl Message for AttestationResponseMsg {
    fn validate(&self) -> bool { true }
    fn message_type_byte(&self) -> u8 { MSG_ATTESTATION_RESPONSE }
}
impl Message for SystemInfoMsg {
    fn validate(&self) -> bool { true }
    fn message_type_byte(&self) -> u8 { MSG_SYSINFO }
}

impl Message for CredentialListMsg {
    fn validate(&self) -> bool { true }
    fn message_type_byte(&self) -> u8 { MSG_LIST_CREDS }
}
impl Message for StatusMsg {
    fn validate(&self) -> bool { true }
    fn message_type_byte(&self) -> u8 { MSG_STATUS_MSG }
}

impl Message for AuthenticateChallengeMsg {
    fn validate(&self) -> bool {
        if self.nonce_challenge.len() > 100 || self.nonce_challenge.len() < 63 {
            #[cfg(debug_assertions)]
            println!("Nonce size of {} is != {NONCE_CHALLENGE_LEN}", self.nonce_challenge.len());

            return false;
        }
        true
    }
    fn message_type_byte(&self) -> u8 { CMD_ATTEST }
}

impl Message for DeleteEntryMsg {
    fn validate(&self) -> bool {
        if self.domain_name.len() > MAX_DOMAIN_LEN || self.domain_name.len() < MIN_DOMAIN_LEN {
            #[cfg(debug_assertions)]
            println!("Domain name is > {MAX_DOMAIN_LEN} bytes or < {MIN_DOMAIN_LEN} bytes!");

            return false;
        }
        true
    }
    fn message_type_byte(&self) -> u8 { CMD_DELETE }
}

impl Message for SetTimeMsg {
    fn validate(&self) -> bool {
        // Check if the timestamp is something valid (later than 10/10/2024)
        if self.unix_timestamp < MIN_TIMESTAMP {
            #[cfg(debug_assertions)]
            println!("UNIX timestamp {} is less than {MIN_TIMESTAMP}", self.unix_timestamp);

            return false;
        }
        true
    }
    fn message_type_byte(&self) -> u8 { CMD_SET_TIME }
}

impl Message for UnlockMsg {
    fn validate(&self) -> bool {
        if self.password.len() < MIN_PW_LEN || self.password.len() > MAX_PW_LEN {
            return false;
        }
        true
    }
    fn message_type_byte(&self) -> u8 { CMD_UNLOCK_VAULT }
}

impl Message for InitVaultMsg {
    fn validate(&self) -> bool {
        if self.password.len() < MIN_PW_LEN || self.password.len() > MAX_PW_LEN {
            return false;
        }
        true
    }
    fn message_type_byte(&self) -> u8 { CMD_INIT_VAULT }
}

impl Message for CreateEntryMsg {
    fn validate(&self) -> bool {
        if self.domain_name.len() > MAX_DOMAIN_LEN || self.domain_name.len() < MIN_DOMAIN_LEN {
            #[cfg(debug_assertions)]
            println!("Domain name is > {MAX_DOMAIN_LEN} bytes or < {MIN_DOMAIN_LEN} bytes!");

            return false;
        }

        // TODO: establish correct values
        // TODO: Base32 encoding is not going to always be the same length (?) how do we handle this?
        if self.totp_secret.len() > MAX_TOTP_SECRET_LEN || self.totp_secret.len() < MIN_TOTP_SECRET_LEN {
            #[cfg(debug_assertions)]
            println!("TOTP secret is > {MAX_TOTP_SECRET_LEN} bytes or < {MIN_TOTP_SECRET_LEN} bytes!");

            return false;
        }

        // Check if secret is valid BASE32 per the spec
        if BASE32.decode(self.totp_secret.as_bytes()).is_err() {
            #[cfg(debug_assertions)]
            println!("TOTP secret is not valid base32!");

            return false;
        }
        true
    }
    fn message_type_byte(&self) -> u8 { CMD_CREATE }
}


impl Message for DisplayCodeMsg {
    fn validate(&self) -> bool {
        if self.domain_name.len() > MAX_DOMAIN_LEN || self.domain_name.len() < MIN_DOMAIN_LEN {
            #[cfg(debug_assertions)]
            println!("Domain name is > {MAX_DOMAIN_LEN} bytes or < {MIN_DOMAIN_LEN} bytes!");

            return false;
        }
        true
    }
    fn message_type_byte(&self) -> u8 { CMD_DISPLAY_CODE }
}