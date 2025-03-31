# System Design

TOTPVault is a device designed to store TOTP secrets in hardware and generate TOTP codes on demand. Built on an ESP32-C3 chip with advanced security features, TOTPVault ensures that your credentials are protected against unauthorized access.

## Security Features

### Secret Storage
  - TOTP secrets are encrypted at rest using AES-256-GCM, ensuring data confidentiality
  - Encryption keys derived from vault password using PBKDF2, device has no knowledge of decryption keys without vault password
  - Secrets are zeroed from memory immediately after use

### System Firmware
  - ESP32-C3 firmware has secure boot enabled with RSA 3072 signature verification, ensuring only trusted firmware can run
  - Firmware is encrypted using hardware-accelerated AES, providing an additional layer of security and mitigating TOCTOU attacks on secure boot
  - Firmware is written in Rust with minimal `unsafe` regions
  - Device can be attested with a challenge to prove itself
  - ESP32 hardware random number generator is used for cryptographic operations

### Hardware Design
  - TOTP secrets are encrypted and stored in on-chip flash memory, substantially complicating attacks to dump or snoop secrets
  - USB interface is delegated to a separate chip (CH343P) from the main microcontroller (ESP32) in order to reduce the attack surface
  - JTAG interfaces are disabled and eFuses locked down
  

## Security Limitations

- Communication between the `ESP32 <-> USB/UART Chip <-> Host` is *unencrypted*. After the vault has been unlocked, it is possible for an attacker to sniff these buses for plain-text TOTP codes and TOTP secrets only if the sniffing occurs while adding a new credential. It is impossible to extract a TOTP secret once it is stored.
  - Mitigation: Lock the vault when not in use or in close proximity to monitor it
