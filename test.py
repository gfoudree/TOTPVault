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
from urllib3.util import current_time

STATUS_MSG = 0x01
SYSINFO_MSG = 0x20
MSG_ATTESTATION_RESPONSE = 0x21
MSG_LIST_CREDS = 0x22
MSG_TOTP_CODE = 0x23

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

def getRespMsg(s):
    r = s.recv()
    assert r[0] == STATUS_MSG
    msg = msgpack.unpackb(r[1:])
    assert len(msg[1]) > 0
    assert msg[0] == False
    return msg[1]

def getErr(s):
    r = s.recv()
    assert r[0] == STATUS_MSG
    msg = msgpack.unpackb(r[1:])
    assert len(msg[1]) > 0
    assert msg[0] == True
    return msg[1]

def getTime(s):
    s.send(b'\x15')
    r = s.recv()
    assert r[0] == SYSINFO_MSG
    msg = msgpack.unpackb(r[1:])
    return msg[3]

def getCreds(s):
    s.send(b'\x12')
    r = s.recv()
    assert r[0] == MSG_LIST_CREDS
    msg = msgpack.unpackb(r[1:])
    return msg[0]

class TestFirmware(unittest.TestCase):
    def setUp(self):
        self.s = serialtube(port='/dev/ttyACM0')
        self.s.timeout = 5
        if self.s.can_recv(1):
            self.s.recv()

        # Lock the vault just in case we're doing runs on a previously unlocked vault
        self.s.send(b'\x1E')
        self.assertIn("Success", getRespMsg(self.s))
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
        self.s.send(buf)
        resp = self.s.recv()
        self.assertTrue(resp[0] == MSG_ATTESTATION_RESPONSE)
        signature = msgpack.unpackb(resp[1:])[0]
        print(f"\nPublic key: {binascii.b2a_hex(b64d(pubkey)).decode()}\nChallenge: {binascii.b2a_hex(randombytes).decode()}\nSignature: {signature}")
        self.assertTrue(checkEd25519Signature(b64d(pubkey), binascii.a2b_hex(signature), randombytes))

    def test_get_host_info(self):
        # Get host info
        self.s.send(b'\x15')
        dev_info_bytes = self.s.recv()
        self.assertTrue(dev_info_bytes[0] == SYSINFO_MSG) # Make sure it's a MSG_SYSINFO response
        # Unpack response
        dev_info = msgpack.unpackb(dev_info_bytes[1:])
        self.assertTrue(dev_info[0] == 128)
        self.assertTrue(dev_info[1] >= 0)
        self.assertTrue(dev_info[2] >= 0)
        self.assertTrue(dev_info[3] >= 0)
        self.assertIn("2FA Cube Version", dev_info[4])
        self.assertTrue(dev_info[5] == True or dev_info[5] == False)
        self.assertTrue(len(b64d(dev_info[6])) == 32) # Length is 32 bytes

    def test_setting_time(self):
        curr_time = getTime(self.s)
        self.assertTrue(curr_time > 0)

        # Set time
        ts = int(datetime.datetime.now().timestamp())
        self.s.send(b'\x10' + msgpack.packb([ts]))
        self.assertIn("Success", getRespMsg(self.s))

        sleep(1)
        # Check again
        new_timestamp = getTime(self.s)
        self.assertGreaterEqual(new_timestamp, ts)
        self.assertGreater(new_timestamp, curr_time)

        # Check setting a bogus value
        self.s.send(b'\x10' + msgpack.packb([2]))
        self.assertTrue(len(getErr(self.s)) > 0)
        self.s.send(b'\x10' + msgpack.packb([0]))
        self.assertTrue(len(getErr(self.s)) > 0)
        self.s.send(b'\x10' + msgpack.packb([100]))
        self.assertTrue(len(getErr(self.s)) > 0)

    def test_init_vault(self):
        # Should fail, password too short
        self.s.send(b'\x1B' + msgpack.packb(["pass"]))
        self.assertIn("Invalid", getErr(self.s))

        self.s.send(b'\x1B' + msgpack.packb([""]))
        self.assertIn("Invalid", getErr(self.s))

        # Try too long of a password
        self.s.send(b'\x1B' + msgpack.packb("p"*129))
        self.assertIn("Invalid", getErr(self.s))

        # Try valid password
        self.s.send(b'\x1B' + msgpack.packb(["password12345!"]))
        self.assertIn("Success", getRespMsg(self.s))

    def test_create(self):
        # Init vault
        pw = "password12345!"
        self.s.send(b'\x1B' + msgpack.packb([pw]))
        self.assertIn("Success", getRespMsg(self.s))

        # Try and list from locked vault
        self.s.send(b"\x12")
        self.assertIn("Locked", getErr(self.s))

        # Try and create from locked vault
        self.s.send(b'\x11' + msgpack.packb(["google.com", "A"*32]))
        self.assertIn("Locked", getErr(self.s))

        # Unlock the vault
        self.s.send(b"\x1A" + msgpack.packb(["badpassword"]))
        self.assertIn("Incorrect Password", getErr(self.s))

        self.s.send(b"\x1A" + msgpack.packb([pw]))
        self.assertIn("Success", getRespMsg(self.s))

        # Vault unlocked, list items, should be empty
        creds = getCreds(self.s)
        self.assertTrue(len(creds) == 0)

        # Create invalid item
        self.s.send(b'\x11' + msgpack.packb(["m", "A"*32]))
        self.assertIn("Invalid", getErr(self.s))

        self.s.send(b'\x11' + msgpack.packb(["google.com", "A"*4]))
        self.assertIn("Invalid", getErr(self.s))

        # Create valid item
        self.s.send(b'\x11' + msgpack.packb(["google.com", "A"*32]))
        self.assertIn("Success", getRespMsg(self.s))

        # Check that it appears in the list
        creds = getCreds(self.s)
        self.assertTrue(len(creds) == 1)
        self.assertTrue("google.com" in creds[0][0])
        self.assertTrue(creds[0][1] == 0) # Check that slot_id = 0

    def test_delete(self):
        # Init & unlock vault
        pw = "password12345!"
        self.s.send(b'\x1B' + msgpack.packb([pw]))
        self.assertIn("Success", getRespMsg(self.s))
        self.s.send(b"\x1A" + msgpack.packb([pw]))
        self.assertIn("Success", getRespMsg(self.s))

        # Create valid item
        totp_secret = base64.b32encode(os.getrandom(32)).decode()
        self.s.send(b'\x11' + msgpack.packb(["test.com", totp_secret]))
        self.assertIn("Success", getRespMsg(self.s))

        # Check that it appears in the list
        creds = getCreds(self.s)
        self.assertTrue(len(creds) == 1)
        self.assertTrue("test.com" in creds[0][0])
        self.assertTrue(creds[0][1] == 0) # Check that slot_id = 0

        # Delete item
        self.s.send(b'\x13' + msgpack.packb(["test.com"]))
        self.assertIn("Success", getRespMsg(self.s))

        # Check that it is NOT in the list
        creds = getCreds(self.s)
        self.assertTrue(len(creds) == 0)

    def test_totp(self):
        # Init & unlock vault
        pw = "password12345!"
        self.s.send(b'\x1B' + msgpack.packb([pw]))
        self.assertIn("Success", getRespMsg(self.s))
        self.s.send(b"\x1A" + msgpack.packb([pw]))
        self.assertIn("Success", getRespMsg(self.s))

        # Set time
        ts = int(datetime.datetime.now().timestamp())
        self.s.send(b'\x10' + msgpack.packb([ts]))
        self.assertIn("Success", getRespMsg(self.s))

        for domain in ["google.com", "cloudflare", "facebook"]:
            # Create valid item
            totp_secret = base64.b32encode(os.getrandom(32)).decode()
            self.s.send(b'\x11' + msgpack.packb([domain, totp_secret]))
            self.assertIn("Success", getRespMsg(self.s))

            # Get code
            self.s.send(b'\x14' + msgpack.packb([domain]))
            totp = pyotp.TOTP(totp_secret, interval=30, digits=6).now()
            resp = self.s.recv()

            # TODO: Maybe think of some better way to do this?
            # Issue where if the timestamp here and timestamp on the device is off by one, the OTP can be different!
            if resp[0] != MSG_TOTP_CODE:
                o = pyotp.TOTP(totp_secret, interval=30, digits=6)
                self.assertTrue(resp[0] == o.at(int(datetime.datetime.now().timestamp()) - 1) or resp[0] == o.at(int(datetime.datetime.now().timestamp()) +1))
            else:
                self.assertTrue(resp[0] == MSG_TOTP_CODE)

            print(f"Domain: {domain}\nSecret key {totp_secret}\nCurrent timestamp " + str(int(datetime.datetime.now().timestamp())))

if __name__ == '__main__':
    unittest.main()
