# Introduction

Welcome to the TOTPVault documentation. This guide will help you understand how to use and manage your TOTPVault device.


# Websites Tested
TOTPVault should work on almost all TOTP-based authentication sites. The list below just shows which ones have been validated to be working

| Website       | Supported |
|---------------|-----------|
| Google        | Y         |
| Digital Ocean |           |
| Amazon        |           |
| Microsoft     |           |
| Instagram     |           |
| Paypal        |           |
| eBay          |           |
| Cloudflare    |           |
| Dropbox       |           |
| Github        |           |
| Gitlab        |           |
| Linkedin      |           |
| Protonmail    |           |


# FAQ
### Why choose ESP32 for the microcontroller?
The ESP32 has Wifi/Bluetooth, does this device use either? No, there is no antenna on the board and the Wifi/Bluetooth stack is disabled in the firmware

### If somebody steals my device, can they generate TOTP codes for my accounts? 
No, as long as your password is strong they cannot unlock the vault and generate codes


# Troubleshooting
### Device does not show up
Try reinserting the device and looking for a USB device with the VID 0x1A86 and PID 0x55D3. 

You can run `dev-info -v` which will print verbose output as to how the device is selected. It is possible another device exists with the same VID/PID in which case use `-p` to specify the path to the exact device

### "unexpected end of file" Error

```
Unable to get device status from: /dev/tty.usbmodem59090561791
	Error = IO error while reading data: unexpected end of file
```
 The device is taking a while to perform operations, increase the timeout in the user application to wait for it