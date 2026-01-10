# TOTPVault CLI Commands

## Sync Time
Synchronize the system time with the device.

**Usage:**
```bash
totpvault-cli sync-time
```

**Example:**
```bash
totpvault-cli sync-time
Successfully synced time to: 1704892800
```

## List Credentials
List all stored credentials on the device.

**Usage:**
```bash
totpvault-cli list-credentials
```

**Example:**
```bash
totpvault-cli list-credentials
[Slot 0]: example.com
[Slot 1]: another-site.org
```

## Delete Credential
Delete a credential for a specific domain.

**Usage:**
```bash
totpvault-cli delete-credential --domain <domain_name>
```

**Example:**
```bash
totpvault-cli delete-credential --domain example.com
Successfully deleted credential
```

## Add Credential
Add a new TOTP credential.

**Usage:**
```bash
totpvault-cli add-credential --domain <domain_name>
```

**Example:**
```bash
totpvault-cli add-credential --domain new-service.net
Enter TOTP Secret Key: JBSWY3DPEHPK3PXP
Successfully added credential
```

## Totp Code
Get TOTP credential for a domain.

**Usage:**
```bash
totpvault-cli totp-code --domain <domain_name>
```

**Example:**
```bash
totpvault-cli totp-code --domain example.com
123456
25s remaining
```

## Init Vault
Initialize/Reset the vault (danger).

**Usage:**
```bash
totpvault-cli init-vault
```

**Example:**
```bash
totpvault-cli init-vault
**************** WARNING ****************
Initializing the vault will WIPE EXISTING CREDENTIALS!
Please make sure you will not be locked out of your accounts!

Do you want to continue? (yes/no): yes
Enter vault password:
Enter vault password (confirm):
Successfully initialized vault!
```

## Device Info
Get device information.

Free/Used slots is always `0` when the vault is locked for security reasons

**Usage:**
```bash
totpvault-cli dev-info
```

**Example:**
```bash
totpvault-cli dev-info
Device Status:
	Vault: Unlocked
	Total Slots: 10
	Used Slots: 2
	Free Slots: 8
	Current Timestamp: 1704892800 delta=0 (In-sync)
	Version: 1.0.0
	ED25519 Public Key: IiG0924qxqsDTs7TF8ZAexXJh2ZsRA5hcd9juC0tBGM=
	Key Fingerprint (SHA256): D9:42:BB:FB:7C:D8:B8:47:3D:AF:72:34:98:2B:44:61:4E:BD:8A:AD:32:97:52:C0:14:9C:96:63:5C:22:39:42
```

## Attest Device
Perform device attestation.

`<public_key>` should be the public key (not fingerprint) of the trusted device to send a challenge to.

**Usage:**
```bash
totpvault-cli attest-dev --key <public_key>
```

**Example:**
```bash
totpvault-cli attest-dev -k IiG0924qxqsDTs7TF8ZAexXJh2ZsRA5hcd9juC0tBGM=`
Public key: IiG0924qxqsDTs7TF8ZAexXJh2ZsRA5hcd9juC0tBGM=
Fingerprint (SHA256): D9:42:BB:FB:7C:D8:B8:47:3D:AF:72:34:98:2B:44:61:4E:BD:8A:AD:32:97:52:C0:14:9C:96:63:5C:22:39:42
Successfully attested device
```

## List Devices
List connected devices.

Use `-v` to view detailed information

**Usage:**
```bash
totpvault-cli list-devices
```

**Example:**
```bash
totpvault-cli list-devices
Found TOTPVault device: /dev/ttyACM0
```

## Unlock Vault
Unlock the vault

**Usage:**
```bash
totpvault-cli unlock-vault
```

**Example:**
```bash
totpvault-cli unlock-vault
Enter password:
Successfully unlocked vault
```

## Lock Vault
Lock the vault

**Usage:**
```bash
totpvault-cli lock-vault
```

**Example:**
```bash
totpvault-cli lock-vault
Locked vault
```
