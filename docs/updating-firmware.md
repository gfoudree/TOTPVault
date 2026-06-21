# Updating Firmware

## Requirements
- Linux or Windows system
  - MacOS is not supported due to a driver issue with the USB <-> UART chip CH343p
  - There is a MacOS driver, but it is untested and the status is unknown: [https://github.com/WCHSoftGroup/ch34xser_macos](https://github.com/WCHSoftGroup/ch34xser_macos_)
- Espressif [`esptool`](https://docs.espressif.com/projects/esptool/en/latest/esp32c3/installation.html)


## Steps
- Install `esptool`: `pip install esptool`

- Download the latest firmware version `flash.bin`

- Push and hold the DFU button on the device (left button) while inserting it into the computer, then release the DFU button

- Identify the device `esptool security-info`

```bash
esptool v5.3.0
Connected to ESP32-C3 on /dev/cu.usbserial-TFGTNDFV:
Chip type:          ESP32-C3 in Secure Download Mode

Security Information:
=====================
Flags: 0x000004f5 (0b10011110101)
Key Purposes: (0, 0, 9, 8, 4, 0, 12)
  BLOCK_KEY0 - USER/EMPTY
  BLOCK_KEY1 - USER/EMPTY
  BLOCK_KEY2 - SECURE_BOOT_DIGEST0
  BLOCK_KEY3 - HMAC_UP
  BLOCK_KEY4 - XTS_AES_128_KEY
  BLOCK_KEY5 - USER/EMPTY
Chip ID: 5
API Version: 3
Secure Boot: Enabled
Secure Boot Key Revocation Status:
        Secure Boot Key1 is Revoked
        Secure Boot Key2 is Revoked

Flash Encryption: Enabled
SPI Boot Crypt Count (SPI_BOOT_CRYPT_CNT): 0x1
Icache in UART download mode: Disabled
JTAG: Permanently Disabled
```

- Flash the new firmware with `esptool --chip esp32c3 -p <SERIAL PORT> --no-stub write-flash --no-compress --force --flash-mode dio --flash-freq 80m --flash-size 4MB 0x0 flash.bin`

```bash
esptool v5.3.0
Connected to ESP32-C3 on /dev/cu.usbserial-TFGTNDFV:
Chip type:          ESP32-C3 in Secure Download Mode

Enabling default SPI flash mode...
Configuring flash size...
Warning: Security features enabled, so not changing any flash settings.
Flash will be erased from 0x00000000 to 0x003fffff...
Wrote 4194304 bytes at 0x00000000 in 421.7 seconds (79.6 kbit/s).
Cannot verify written data if encrypted or in secure download mode.

Hard resetting via RTS pin...
```

- Unplug and reinsert the device
