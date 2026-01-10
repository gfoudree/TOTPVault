# Updating Firmware

To update the firmware on your TOTPVault device, you will need to put it into DFU (Device Firmware Update) mode.

## Steps to update firmware:

1.  **Prepare the device**: Hold down the DFU button on the TOTPVault device.
2.  **Connect to computer**: While holding the DFU button, plug the device into your computer's USB port.
3.  **Release DFU button**: Once connected, you can release the DFU button. The device should now be in DFU mode, ready to receive new firmware.

Once in DFU mode, you can use the appropriate flashing tool (e.g., `esptool.py` or `cargo espflash`) to upload the new firmware. Specific commands will depend on your development environment and the firmware image.
