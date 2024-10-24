import base64
import copy
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

STATUS_MSG = 0x01
SYSINFO_MSG = 0x20
MSG_ATTESTATION_RESPONSE = 0x21

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

# Return a tuple of a decoded STATUS_MSG -> (is_error (boolean), str (string))
def getResponse(buf):
    if buf[0] == STATUS_MSG:
        decoded = msgpack.unpackb(buf[1:])
        return (decoded[0], decoded[1])
    else:
        return (None, None)

class TestFirmware(unittest.TestCase):
    def setUp(self):
        self.s = serialtube(port='/dev/ttyACM0')
        self.s.timeout = 5
        if self.s.can_recv(1):
            self.s.recv()

        # Lock the vault just in case we're doing runs on a previously unlocked vault

        self.s.send(b'\x1E')
        self.assertIn(b"Success", self.s.recv())
    def test_attestation(self):
        # Get pubkey
        self.s.send(b'\x15')
        dev_info_bytes = self.s.recv()
        self.assertTrue(dev_info_bytes[0] == SYSINFO_MSG) # Make sure it's a MSG_SYSINFO response
        # Unpack response
        dev_info = msgpack.unpackb(dev_info_bytes[1:])
        pubkey = dev_info[6]

        self.assertTrue(len(b64d(pubkey)) == 32) # Length is 32 bytes

        # Generate nonce
        randombytes = os.urandom(64)

        # Send challenge
        buf = b'\x1C' + msgpack.packb([b64e(randombytes)])
        print(hexdump(buf))
        self.s.send(buf)
        resp = self.s.recv()
        self.assertTrue(resp[0] == MSG_ATTESTATION_RESPONSE)
        signature = msgpack.unpackb(resp[1:])[0]
        print(f"\nPublic key: {binascii.b2a_hex(b64d(pubkey)).decode()}\nChallenge: {binascii.b2a_hex(randombytes).decode()}\nSignature: {signature}")
        self.assertTrue(checkEd25519Signature(b64d(pubkey), binascii.a2b_hex(signature), randombytes))
        # TODO: Run LOTS of tests of this, for some reason signatures are occasionally failing
        """
        Public key: b'8242ac6f17c46c30bd804cfe61dc8404155face61b26f1d2e35e71a53ab38db5'
        Challenge: b'839bfeabf3b1b5d490e5421cf0083221ab565ed7cbcdb378cbb2e6154bd6edc1370c47aca051fcbb9beac10bce9ab7c3bb73ff114f8d19d7da34f30ad9d11b2b'
        Signature: 220894384B216D5DC204B34B65F988F8C90F087F641F854DC978F09DECB8B2618108555BC802797E1A88650350CC7A493091BCB25C81602A84652AB73A1B5703
        FAIL
        
        Public key: b'8242ac6f17c46c30bd804cfe61dc8404155face61b26f1d2e35e71a53ab38db5'
        Challenge: b'8e60e273713eeae67fdcc7bba65aa568581ba419dd8d1ef3c33107079bbc36fb01dbf6115c92b554aa0d990d392b09250ac44897068e7f0be9902be20d79a87c'
        Signature: 424C62BE5FB91FA6485D71F8A2FD0ED9E67219378C65F1316C96840BDC6075C231617E7BE2C0C96E75EE6DCDFB6708839DF1B7B45CDE71246F727583BEA90506
        FAIL

        """

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