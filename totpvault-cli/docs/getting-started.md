# Getting Started

Follow these steps to set up a new TOTPVault device:


## Find the TOTPVault device
```bash
$ totpvault-cli dev-info
Device Status:
	Vault: Locked
	Total Slots: 64
	Used Slots: 0
	Free Slots: 0
	Current Timestamp: 89 (Out-of-Sync)
	Version: 2FA Cube Version 0.1
	Public Key: 2ppFZmElF9eAIi2QaJtwG9y2g3oJAPU/izSje4AbTFQ=
	Key Fingerprint: 4C:FD:D5:D2:9B:70:59:8A:...
```

If you don't see the device, try running with `-v` to see the verbose output

## Initialize the vault
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
```bash
$ totpvault-cli sync-time
Successfully synced time
```

## Verify time-sync and unlocked status
```bash
$ totpvault-cli dev-info
Device Status:
	Vault: Unlocked
	Total Slots: 64
	Used Slots: 0
	Free Slots: 64
	Current Timestamp: 1743270512 (In-sync)
```
Status shows `Vault: Unlocked` and `Current Timestamp: 1743270512 (In-sync)` showing the vault's time is in sync

## Add a credential
```bash
$ totpvault-cli add-credential --domain-name google.com
```
Refer to the [Commands](commands.md) section for detailed usage of each command.
