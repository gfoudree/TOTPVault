# Getting Started

## Installation

First, clone the repository and build the `totpvault-cli` tool:

```bash
git clone https://github.com/gfoudree/totpvault
cd totpvault/totpvault-cli
cargo build -r
```
The executable will be located at `target/release/totpvault-cli`. You can optionally move it to a directory in your `PATH` for easier access.

## Find the TOTPVault device
Insert the device into your computer and search for it
```bash
$ totpvault-cli dev-info

Device Status:
	Vault: Locked
	Total Slots: 64
	Used Slots: 0
	Free Slots: 0
	Current Timestamp: 89 (Out-of-Sync)
	Version: TOTPVault Version 0.1
	Public Key: 2ppFZmElF9eAIi2QaJtwG9y2g3oJAPU/izSje4AbTFQ=
	Key Fingerprint: 4C:FD:D5:D2:9B:70:59:8A:...
```

If you don't see the device, try running with `-v` to see the verbose output. You can manually specify a device with `-p`


## Initialize the vault
Initialize the vault with a strong password. This wipes all existing credentials in the vault, beware!
```bash
$ totpvault-cli init-vault

**************** WARNING ****************
Initializing the vault will WIPE EXISTING CREDENTIALS!
Please make sure you will not be locked out of your accounts!

Do you want to continue? (yes/no):
yes
Enter vault password:
Enter vault password (confirm):
Successfully initialized vault!
```

## Unlock the vault
```bash
$ totpvault-cli unlock-vault

Enter password:
Successfully unlocked vault
```

## Sync time
Time must be synced to the vault on power reset as there is no battery-powered clock. **Inaccurate time will result in invalid TOTP codes**

```bash
$ totpvault-cli sync-time

Successfully synced time to: 2026-01-10 05:44:50.866425 UTC
```

## Verify time-sync and unlocked status
```bash
$ totpvault-cli dev-info

Device Status:
	Vault: Unlocked
	Total Slots: 64
	Used Slots: 0
	Free Slots: 64
	Current Timestamp: 1768023870 delta=2 (In-sync)
	Version: TOTPVault Version 0.1
	ED25519 Public Key: IiG0924qxqsDTs7TF8ZAexXJh2ZsRA5hcd9juC0tBGM=
	Key Fingerprint (SHA256): D9:42:BB:FB:7C:D8:B8:47:3D:AF:72:34:98:2B:44:61:4E:BD:8A:AD:32:97:52:C0:14:9C:96:63:5C:22:39:42
```
`Vault: Unlocked` and `Current Timestamp: 1768023870 (In-sync)` shows that the vault's time is in sync

Note the key fingerprint `D9:42:BB:FB:7C:D8...`. This is the fingerprint of the public key of the device which can be used to authenticate it.

## Add a credential
Login to the account you wish to add and enable a new TOTP credential

When the QR code displays, there should be a option such as "can't scan code" which displays a string such as `r7uk mfjw zboh 3x3u ccij bptu leeq thk6`

Next, run the following command pasting the string from above
```bash
$ totpvault-cli add-credential --domain-name google.com

Enter TOTP Secret Key:
Successfully added credential
```

It is wise to keep a backup 2FA device/method available in case you lose your TOTPVault token!

## List credentials
```bash
$ totpvault-cli list-credentials

[Slot 0]: google.com
```

## Get TOTP code
If the code is incorrect, wait until the next code rolls over (or 30+ sec) since there can be a small delay with the device generating the code
```bash
$ totpvault-cli totp-code -d google.com

056086
11s remaining
```

Refer to the [Commands](commands.md) section for detailed usage of each command.
