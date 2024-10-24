import base64
import os

from pwn import *
import struct
import datetime
import msgpack
import unittest

from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
import binascii
import pyotp

# binascii.a2b_hex('aabbcc')
def checkEd25519Signature(public_key_bytes, signature_bytes, message_bytes):
    # Load the public key
    public_key = ed25519.Ed25519PublicKey.from_public_bytes(public_key_bytes)

    try:
        # Verify the signature
        public_key.verify(signature_bytes, message_bytes)
        return True
    except InvalidSignature:
        return False

class TestFirmware(unittest.TestCase):
    def setUp(self):
        self.s = serialtube(port='/dev/ttyACM1')
        self.s.timeout = 5
        if self.s.can_recv(1):
            self.s.recv()

        # Lock the vault just in case we're doing runs on a previously unlocked vault

        self.s.send(b'\x1E')
        self.assertIn(b"Success", self.s.recv())
    def test_attestation(self):
        # Get pubkey
        self.s.send(b'\x1D')
        pubkey = self.s.recv().replace(b'\n', b'')
        print(f"Public key: {pubkey}")
        self.assertTrue(len(pubkey) == 64) # Length is 32 bytes but in hex, so 64

        # Generate nonce
        randombytes = os.urandom(64)

        # Send challenge
        self.s.send(b'\x1C' + msgpack.packb([randombytes], use_bin_type=True))
        resp = self.s.recv().replace(b'\n', b'')

        self.assertTrue(checkEd25519Signature(binascii.a2b_hex(pubkey), binascii.a2b_hex(resp), randombytes))

    def test_get_host_info(self):
        # Get host info
        self.s.send(b'\x15')
        resp = self.s.recv()
        self.assertIn(b"2FA", resp)
        self.assertIn(b"System Time:", resp)

    def test_setting_time(self):
        # Get host info
        self.s.send(b'\x15')
        resp = self.s.recv()
        current_timestamp = int(resp.decode().split('\n')[1].split(':')[1][1:])

        # Set time
        ts = int(datetime.datetime.now().timestamp())
        self.s.send(b'\x10' + msgpack.packb([ts]))
        self.assertIn(b"Success", self.s.recv())

        sleep(1)

        # Check again
        self.s.send(b'\x15')
        resp = self.s.recv()
        new_timestamp = int(resp.decode().split('\n')[1].split(':')[1][1:])

        self.assertGreaterEqual(new_timestamp, ts)
        self.assertGreater(new_timestamp, current_timestamp)

    def test_setting_invalid_time(self):
        # 105 is way too low
        self.s.send(b'\x10' + msgpack.packb([105]))
        self.assertNotIn(b"Success", self.s.recv())

    def test_init_vault(self):
        # Should fail, password too short
        self.s.send(b'\x1B' + msgpack.packb(["pass"]))
        self.assertIn(b"Invalid", self.s.recv())

        self.s.send(b'\x1B' + msgpack.packb([""]))
        self.assertIn(b"Invalid", self.s.recv())

        # Try too long of a password
        self.s.send(b'\x1B' + msgpack.packb("p"*129))
        self.assertIn(b"Invalid", self.s.recv())

        # Try valid password
        self.s.send(b'\x1B' + msgpack.packb(["password12345!"]))
        self.assertIn(b"Success", self.s.recv())

    def test_create(self):
        # Init vault
        pw = "password12345!"
        self.s.send(b'\x1B' + msgpack.packb([pw]))
        self.assertIn(b"Success", self.s.recv())

        # Try and list from locked vault
        self.s.send(b"\x12")
        self.assertIn(b"Vault locked", self.s.recv())

        # Try and create from locked vault
        self.s.send(b'\x11' + msgpack.packb(["google.com", "A"*32]))
        self.assertIn(b"Vault locked", self.s.recv())

        # Unlock the vault
        self.s.send(b"\x1A" + msgpack.packb(["badpassword"]))
        self.assertIn(b"Wrong password", self.s.recv())

        self.s.send(b"\x1A" + msgpack.packb([pw]))
        self.assertIn(b"Success", self.s.recv())

        # Vault unlocked, list items
        self.s.send(b'\x12')
        self.assertIn(b"Creds: []", self.s.recv())

        # Create invalid item
        self.s.send(b'\x11' + msgpack.packb(["m", "A"*32]))
        self.assertIn(b"Invalid", self.s.recv())

        self.s.send(b'\x11' + msgpack.packb(["google.com", "A"*4]))
        self.assertIn(b"Invalid", self.s.recv())

        # Create valid item
        self.s.send(b'\x11' + msgpack.packb(["google.com", "A"*32]))
        self.assertIn(b"Success", self.s.recv())

        # Check that it appears in the list
        self.s.send(b'\x12')
        r = self.s.recv()
        self.assertIn(b"google.com", r)

    def test_delete(self):
        # Init & unlock vault
        pw = "password12345!"
        self.s.send(b'\x1B' + msgpack.packb([pw]))
        self.assertIn(b"Success", self.s.recv())
        self.s.send(b"\x1A" + msgpack.packb([pw]))
        self.assertIn(b"Success", self.s.recv())

        # Create valid item
        totp_secret = base64.b32encode(os.getrandom(32)).decode()
        self.s.send(b'\x11' + msgpack.packb(["test.com", totp_secret]))
        self.assertIn(b"Success", self.s.recv())

        # Check that it appears in the list
        self.s.send(b'\x12')
        self.assertIn(b"test.com", self.s.recv())

        # Delete item
        self.s.send(b'\x13' + msgpack.packb(["test.com"]))
        self.assertIn(b"Success", self.s.recv())

        # Check that it is NOT in the list
        self.s.send(b'\x12')
        self.assertNotIn(b"test.com", self.s.recv())

    def test_totp(self):
        # Init & unlock vault
        pw = "password12345!"
        self.s.send(b'\x1B' + msgpack.packb([pw]))
        self.assertIn(b"Success", self.s.recv())
        self.s.send(b"\x1A" + msgpack.packb([pw]))
        self.assertIn(b"Success", self.s.recv())

        # Set time
        ts = int(datetime.datetime.now().timestamp())
        self.s.send(b'\x10' + msgpack.packb([ts]))
        self.assertIn(b"Success", self.s.recv())

        for domain in ["google.com", "cloudflare", "facebook"]:
            # Create valid item
            totp_secret = base64.b32encode(os.getrandom(32)).decode()
            self.s.send(b'\x11' + msgpack.packb([domain, totp_secret]))
            self.assertIn(b"Success", self.s.recv())

            # Get code
            self.s.send(b'\x14' + msgpack.packb([domain]))
            resp = self.s.recv()
            print(resp)
            print(f"Secret key {totp_secret}\n Current timestamp " + str(datetime.datetime.now().timestamp()))

            totp = pyotp.TOTP(totp_secret, interval=30, digits=6).now()
            returned_totp = resp.decode().split(':')[1].replace('\n', '').replace(' ', '')
            self.assertEqual(returned_totp, totp)

if __name__ == '__main__':
    unittest.main()