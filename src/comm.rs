use data_encoding::BASE32;
use serde::{Deserialize, Serialize};

const MIN_TOTP_SECRET_LEN: usize = 16;
const MAX_TOTP_SECRET_LEN: usize = 64;
const MAX_DOMAIN_LEN: usize = 64;
const MIN_DOMAIN_LEN: usize = 2;
const MIN_PW_LEN: usize = 12;
const MAX_PW_LEN: usize = 128;
const MIN_TIMESTAMP: u64 = 1728590640;
pub const NONCE_CHALLENGE_LEN: usize = 64;

pub trait Validate {
    fn validate(&self) -> bool;
}

#[derive(Serialize, Deserialize, Debug)]
pub struct CreateEntryMsg {
    pub domain_name: String,
    pub totp_secret: String,
}

#[derive(Serialize, Deserialize, Debug)]
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

#[derive(Serialize, Deserialize, Debug)]
pub struct InitVaultMsg {
    pub password: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct DisplayCodeMsg {
    pub domain_name: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct AuthenticateChallengeMsg {
    pub nonce_challenge: Vec<u8>,
}

impl Validate for AuthenticateChallengeMsg {
    fn validate(&self) -> bool {
        if self.nonce_challenge.len() != NONCE_CHALLENGE_LEN {
            #[cfg(debug_assertions)]
            println!("Nonce size of {} is != {NONCE_CHALLENGE_LEN}", self.nonce_challenge.len());

            return false;
        }
        true
    }
}

impl Validate for DeleteEntryMsg {
    fn validate(&self) -> bool {
        if self.domain_name.len() > MAX_DOMAIN_LEN || self.domain_name.len() < MIN_DOMAIN_LEN {
            #[cfg(debug_assertions)]
            println!("Domain name is > {MAX_DOMAIN_LEN} bytes or < {MIN_DOMAIN_LEN} bytes!");
    
            return false;
        }
        true
    }
}

impl Validate for SetTimeMsg {
    fn validate(&self) -> bool {
        // Check if the timestamp is something valid (later than 10/10/2024)
        if self.unix_timestamp < MIN_TIMESTAMP {
            #[cfg(debug_assertions)]
            println!("UNIX timestamp {} is less than {MIN_TIMESTAMP}", self.unix_timestamp);

            return false;
        }
        true
    }
}

impl Validate for UnlockMsg {
    fn validate(&self) -> bool {
        if self.password.len() < MIN_PW_LEN || self.password.len() > MAX_PW_LEN {
            return false;
        }
        true
    }
}

impl Validate for InitVaultMsg {
    fn validate(&self) -> bool {
        if self.password.len() < MIN_PW_LEN || self.password.len() > MAX_PW_LEN {
            return false;
        }
        true
    }
}

impl Validate for CreateEntryMsg {
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
}


impl Validate for DisplayCodeMsg {
    fn validate(&self) -> bool {
        if self.domain_name.len() > MAX_DOMAIN_LEN || self.domain_name.len() < MIN_DOMAIN_LEN {
            #[cfg(debug_assertions)]
            println!("Domain name is > {MAX_DOMAIN_LEN} bytes or < {MIN_DOMAIN_LEN} bytes!");

            return false;
        }
        true
    }
}