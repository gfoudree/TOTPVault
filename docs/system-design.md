# System Design

## Security Features

### Secret Storage
  - TOTP secrets are encrypted at rest using AES-256-GCM, ensuring data confidentiality
  - Encryption keys derived from vault password using PBKDF2, device has no knowledge of decryption keys without vault password
  - The keys are never stored on the device (ie. the device cannot decrypt any secrets without the user providing the vault password)
  - Encrypted TOTP secrets are stored in NVS (flash) on the same die as the microcontroller, making it difficult to sniff/extract them
  - Secrets are zeroed from memory immediately after use

![System Diagram](/images/secret_diagram.png){: .center }

### System Firmware
  - ESP32-C3 firmware has secure boot enabled with RSA 3072 signature verification, ensuring only trusted firmware can run
  - Firmware is encrypted using hardware-accelerated AES, providing an additional layer of security and mitigating TOCTOU attacks on secure boot
  - Firmware is written in Rust with minimal `unsafe` regions
  - Device can be attested with a challenge to prove itself
  - ESP32-C3 hardware random number generator is used for cryptographic operations

    ![HW RNG Design](/images/hwrng_diagram.png){: .center }

### Hardware Design
  - TOTP secrets are encrypted and stored in on-chip flash memory, substantially complicating attacks to dump or snoop secrets
  - USB interface is delegated to a separate chip (CH343P) from the main microcontroller (ESP32-C3) in order to isolate any USB-level exploits from the main uC

    ![USB Isolation](/images/usb_isolation_diagram.png){: .center }

  - JTAG interfaces are disabled and eFuses locked down

## Security Limitations

- Communication between the `ESP32 <-> USB/UART Chip <-> Host` is *unencrypted*. After the vault has been unlocked, it is possible for an attacker to sniff these buses for plain-text TOTP codes and TOTP secrets (but only if the sniffing occurs while adding a new credential). It is impossible to extract a TOTP secret once it is stored.
