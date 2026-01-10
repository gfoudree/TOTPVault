
# TOTPVault

TOTPVault is a secure hardware vault for storing TOTP codes for two-factor authentication. It is compatible with websites and applications which support authenticators such as Google Authenticator or Authy.

## Installation

First, clone the repository and build the `totpvault-cli` tool:

```bash
git clone https://gitlab.com/gfoudree/totpvault
cd totpvault-cli
cargo build -r
```
The executable will be located at `target/release/totpvault-cli`. You can optionally move it to a directory in your `PATH` for easier access.

## Secrets
Secrets are encrypted with AES256-CBC encryption. Keys are derived from the user-supplied vault password which is fed into PBKDF2 to generate a cryptographically-secure key. The keys are *never* stored on the device (ie. the device cannot decrypt any secrets without the user providing the vault password). All cryptographic operations are done in software and do not use the ESP32’s hardware encryption modules except for the HWRNG.

Secrets are encrypted and stored in NVS (flash) on the same die as the microcontroller, making it hard to sniff or extract them. No plain-text secrets are stored (except in memory). Once secrets are no longer needed, they are zeroed out in memory.

## Platform
The system firmware is written in Rust and runs on the ESP32-C3 (RISC-V) chip. Firmware is verified via secure boot which help mitigate evil-maid or other attacks.

## FAQ

#### Why ESP32-C3?

The ESP32 platform was chosen as it provides security features such as secure boot and hardware RNG. It is affordable and has a decent track record for security.

## Roadmap

- Support additional ESP32 hardware security features such as the Trusted Execution Engine (TEE)

- Support USB-C connectors

