# TOTP Vault CLI Commands

## Sync Time
Synchronize the system time with the device.

Usage:
```
totpvault-cli sync-time
```

## List Credentials
List all stored credentials on the device.

Usage:
```
totpvault-cli list-credentials
```

## Delete Credential
Delete a credential for a specific domain.

Usage:
```
totpvault-cli delete-credential --domain <domain_name>
```

## Add Credential
Add a new TOTP credential.

Usage:
```
totpvault-cli add-credential --domain <domain_name>
```

## Totp Code
Get TOTP credential for a domain.

Usage:
```
totpvault-cli totp-code --domain <domain_name>
```

## Init Vault
Initialize/Reset the vault (danger).

Usage:
```
totpvault-cli init-vault
```

## Device Info
Get device information.

Free/Used slots is always `0` when the vault is locked for security reasons

Usage:
```
totpvault-cli dev-info
```

## Attest Device
Perform device attestation.

`<public_key>` should be the public key (not fingerprint) of the trusted device to send a challenge to.

Usage:
```
totpvault-cli attest-dev --key <public_key>
```

## List Devices
List connected devices. 

Use `-v` to view detailed information

Usage:
```
totpvault-cli list-devices
```

## Unlock Vault
Unlock the vault

Usage:
```
totpvault-cli unlock-vault
```

## Lock Vault
Lock the vault

Usage:
```
totpvault-cli lock-vault
```
