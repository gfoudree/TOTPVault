#!/usr/bin/env bash
RUST_FIRMWARE=target/riscv32imc-esp-espidf/release/totpvault-firmware
ELF_FIRMWARE=/tmp/totpvault-firmware.elf
ELF_FIRMWARE_SIGNED=target/riscv32imc-esp-espidf/release/totpvault-firmware-signed.elf
ELF_FIRMWARE_SIGNED_ENCRYPTED=target/riscv32imc-esp-espidf/release/totpvault-firmware-signed.enc.elf

BOOTLOADER=target/riscv32imc-esp-espidf/release/bootloader.bin
BOOTLOADER_SIGNED=target/riscv32imc-esp-espidf/release/bootloader-signed.bin
BOOTLOADER_ENCRYPTED=target/riscv32imc-esp-espidf/release/bootloader-signed.enc.bin

PARTITION_TABLE=target/riscv32imc-esp-espidf/release/partition-table.bin
PARTITION_TABLE_SIGNED=target/riscv32imc-esp-espidf/release/partition-table-signed.bin
PARTITION_TABLE_ENCRYPTED=target/riscv32imc-esp-espidf/release/partition-table-signed.enc.bin

SECUREBOOT_RSA_KEYFILE=secureboot_key.pem
FLASH_ENCRYPTION_AES_KEYFILE=flash_encryption_key.bin

FLASH_IMAGE=flash.bin
EFUSE_FILE=qemu_efuse.bin


efuse_cmd() {
	espefuse.py -p $ESPPORT --chip esp32c3 --before=no_reset --do-not-confirm "$@"
}

setup_efuses_qemu() {
  # Set chip revision to be 3 (needed for QEMU)
  efuse_cmd burn_efuse WAFER_VERSION_MINOR_LO 3
  setup_efuses
}

setup_efuses() {
	# Burn HMAC key for NVS encryption
	efuse_cmd burn_key BLOCK_KEY3 hmac_key.bin HMAC_UP

	# Burn AES key for flash encryption
	efuse_cmd burn_key BLOCK_KEY4 flash_encryption_key.bin XTS_AES_128_KEY

	# Sets flash encryption to release mode
	efuse_cmd burn_efuse SPI_BOOT_CRYPT_CNT 1

	# Burn public RSA key for secure boot and enable secure boot
	efuse_cmd burn_key BLOCK_KEY2 digest.bin SECURE_BOOT_DIGEST0
	efuse_cmd burn_efuse SECURE_BOOT_EN

	# Protect the secureboot key eFuse so that reading can never be disabled (which would brick the device)
	efuse_cmd write_protect_efuse RD_DIS

	# Revoke other key slots for secure boot signing
	efuse_cmd burn_efuse SECURE_BOOT_KEY_REVOKE1
	efuse_cmd burn_efuse SECURE_BOOT_KEY_REVOKE2

	# Disable: software access to JTAG, direct boot, USB switch to JTAG, JTAG completely, UART bootloader encryption access, UART cache
	efuse_cmd burn_efuse SOFT_DIS_JTAG 0x1 DIS_DIRECT_BOOT 0x1 DIS_USB_JTAG 0x1 DIS_PAD_JTAG 0x1 DIS_DOWNLOAD_MANUAL_ENCRYPT 0x1 DIS_DOWNLOAD_ICACHE 0x1

	# Write protect eFuses (also write protects eFuses from above)
	efuse_cmd write_protect_efuse DIS_ICACHE SECURE_BOOT_EN SOFT_DIS_JTAG SPI_BOOT_CRYPT_CNT SECURE_BOOT_KEY_REVOKE1 SECURE_BOOT_KEY_REVOKE2

	# Enable secure ROM download. WARNING: all writing/reading of eFuses are disabled after this
	efuse_cmd burn_efuse ENABLE_SECURITY_DOWNLOAD
}

gen_keys() {
	dd if=/dev/random of=hmac_key.bin bs=1 count=32
	openssl genrsa -out secureboot_key.pem -verbose 3072
	espsecure.py generate_flash_encryption_key flash_encryption_key.bin
	espsecure.py digest_sbv2_public_key --keyfile secureboot_key.pem --output digest.bin
}

sign_firmware() {
  # Need to create an ESP image from the ELF file
  esptool.py --chip esp32c3 elf2image --output $ELF_FIRMWARE --version 2 $RUST_FIRMWARE
  
  # Sign the image
  espsecure.py sign_data --version 2 --keyfile $SECUREBOOT_RSA_KEYFILE --output $ELF_FIRMWARE_SIGNED $ELF_FIRMWARE

  # Sign the bootloader & partition table
  espsecure.py sign_data --version 2 --keyfile $SECUREBOOT_RSA_KEYFILE --output $BOOTLOADER_SIGNED $BOOTLOADER
  espsecure.py sign_data --version 2 --keyfile $SECUREBOOT_RSA_KEYFILE --output $PARTITION_TABLE_SIGNED $PARTITION_TABLE

  # Encrypt the components
  espsecure.py encrypt_flash_data --aes_xts --keyfile $FLASH_ENCRYPTION_AES_KEYFILE --address 0x0 --output $BOOTLOADER_ENCRYPTED $BOOTLOADER_SIGNED
  espsecure.py encrypt_flash_data --aes_xts --keyfile $FLASH_ENCRYPTION_AES_KEYFILE --address 0x10000 --output $PARTITION_TABLE_ENCRYPTED $PARTITION_TABLE_SIGNED
  espsecure.py encrypt_flash_data --aes_xts --keyfile $FLASH_ENCRYPTION_AES_KEYFILE --address 0x30000 --output $ELF_FIRMWARE_SIGNED_ENCRYPTED $ELF_FIRMWARE_SIGNED
  
  # Merge the components
  esptool.py --chip esp32c3 merge_bin --fill-flash-size 4MB -o $FLASH_IMAGE --flash_mode dio --flash_freq 80m --flash_size 4MB 0x0 $BOOTLOADER_ENCRYPTED 0x10000 $PARTITION_TABLE_ENCRYPTED 0x30000 $ELF_FIRMWARE_SIGNED_ENCRYPTED
}

verify_signature() {
  # Display the signature to check
  echo "Checking firmware..."
  espsecure.py signature_info_v2 $ELF_FIRMWARE_SIGNED
  espsecure.py verify_signature --version 2 --keyfile $SECUREBOOT_RSA_KEYFILE $ELF_FIRMWARE_SIGNED

  echo "Checking bootloader..."
  espsecure.py signature_info_v2 $BOOTLOADER_SIGNED
  espsecure.py verify_signature --version 2 --keyfile $SECUREBOOT_RSA_KEYFILE $BOOTLOADER_SIGNED
}

qemu_build_efuses() {
  dd if=/dev/zero bs=1K count=1 of=$EFUSE_FILE
  export ESPPORT=socket://localhost:5555
  qemu-system-riscv32 -nographic \
                      -machine esp32c3 \
                      -global driver=esp32c3.gpio,property=strap_mode,value=0x02 \
                      -drive file=$EFUSE_FILE,if=none,format=raw,id=efuse \
                      -global driver=nvram.esp32c3.efuse,property=drive,value=efuse \
                      -serial tcp::5555,server,nowait
}

qemu_test() {
  qemu-system-riscv32 -nographic \
                      -M esp32c3 \
                      -drive file=$FLASH_IMAGE,if=mtd,format=raw \
                      -drive file=$EFUSE_FILE,if=none,format=raw,id=efuse \
                      -global driver=nvram.esp32c3.efuse,property=drive,value=efuse \
                      -serial mon:stdio
}

flash_device() {
  esptool.py --chip esp32c3 -p $ESPPORT --no-stub write_flash --no-compress --force --flash_mode dio --flash_freq 80m --flash_size 4MB 0x0 $BOOTLOADER_ENCRYPTED 0x10000 $PARTITION_TABLE_ENCRYPTED 0x30000 $ELF_FIRMWARE_SIGNED_ENCRYPTED
  rm $ELF_FIRMWARE
}

# Source the export.sh in the ESP-IDF folder first

sign_firmware
verify_signature
#qemu_test
flash_device
