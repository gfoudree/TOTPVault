# System Design

The TOTPVault is a secure hardware device designed to store TOTP secrets in hardware and generate TOTP codes on demand. Built on an ESP32-C3 chip with advanced security features, the TOTPVault ensures that your credentials are protected against unauthorized access.

## Hardware Overview

- **ESP32-C3 RISC-V Microcontroller**: High-performance microcontroller for efficient code execution.
- **Isolated USB Stack**: The USB stack is isolated to a separate USB-to-UART chip (CH343P) to reduce the attack surface and protect the main chip that stores TOTP secrets.

## Security Features

- **Advanced Encryption**: TOTP secrets are encrypted at rest using AES-256-GCM with unique nonces for each code generation, ensuring data confidentiality.
- **Secure Boot Implementation**:
  - RSA 3072 signature verification during boot ensures only trusted firmware can run.
  - Trusted firmware execution and hardware attestation validate the integrity of the device's intellectual property.
- **Firmware Protection**:
  - Firmware is encrypted at rest using AES-256-GCM, providing an additional layer of security.
  - Hardware-based attestation mechanisms ensure firmware integrity.
  - Tamper-resistant design with secure boot enforced at the hardware level prevents unauthorized modifications.

## Key Management

- **Key Generation**: Keys are generated using high-entropy random number generators to ensure cryptographic strength.
- **Key Storage**: All encryption and signing keys are stored in hardware-secured storage, isolated from system software to prevent unauthorized access.
- **Key Rotation**: Keys are updated securely through the device's initialization process, maintaining security over time.
- **Key Derivation**: Passwords are securely derived using the PBKDF2 algorithm, and the resulting keys are protected by the hardware-level encryption stack.

## Storage Mechanism

- **Data Encryption**:
  - TOTP codes are stored in AES-256-GCM encrypted format with random nonces for each code generation operation.
  - GHASH authentication ensures data integrity and consistency.
- **Key Derivation**:
  - Passwords are securely derived using the PBKDF2 algorithm, ensuring that even if a password is compromised, the encryption keys remain secure.

## Firmware Protection

- **Firmware Encryption**:
  - The entire firmware image is encrypted at rest using AES-256-GCM to protect against unauthorized access.
  - Hardware-based attestation verifies the integrity of the firmware during boot.
- **Secure Boot Process**:
  - Signature verification ensures that only trusted code runs on the device, preventing malicious firmware from executing.
  - Secure boot bypass protection is enforced to maintain security.
- **Firmware Update**:
  - Firmware updates require secure boot setup and encryption context validation to ensure that only authorized updates can be applied.

## Firmware Security

- **Rust Programming Language**: The firmware is written in Rust, a systems programming language known for its memory safety and concurrency features. This choice enhances security by preventing common vulnerabilities such as buffer overflows and data races.
- **Memory Safety**: Rust's ownership model ensures that memory is managed safely without the need for manual garbage collection or reference counting, reducing the risk of memory-related vulnerabilities.