"""Unit tests for Blowfish against Schneier's official published vectors."""

import unittest

from src.Blowfish import Blowfish
from tests.vectors import (BLOWFISH_OFFICIAL, BLOWFISH_SET_KEY,
                           BLOWFISH_SET_KEY_PT)


class BlowfishKATTestCase(unittest.TestCase):
    """The 34-entry official ECB set and the 21 official set_key vectors.

    Keys under 4 bytes (32 bits) fall outside the specification and are
    rejected, so the 1- to 3-byte set_key vectors are deliberately unused.
    """

    def test_official_ecb_encrypt(self):
        """Encrypt every official ECB vector."""
        for i, (key, pt, ct) in enumerate(BLOWFISH_OFFICIAL):
            with self.subTest(vector=f"official ecb {i + 1:02d}"):
                cipher = Blowfish()
                cipher.generate_keys(bytes.fromhex(key))
                self.assertEqual(cipher.encrypt_block(bytes.fromhex(pt)),
                                 bytes.fromhex(ct))

    def test_official_ecb_decrypt(self):
        """Decrypt every official ECB vector."""
        for i, (key, pt, ct) in enumerate(BLOWFISH_OFFICIAL):
            with self.subTest(vector=f"official ecb {i + 1:02d}"):
                cipher = Blowfish()
                cipher.generate_keys(bytes.fromhex(key))
                self.assertEqual(cipher.decrypt_block(bytes.fromhex(ct)),
                                 bytes.fromhex(pt))

    def test_set_key_vectors(self):
        """Encrypt the fixed plaintext under 4- to 24-byte keys.

        The key schedule cycles short keys, so these mostly exercise the
        schedule rather than the round function.
        """
        for key, ct in BLOWFISH_SET_KEY:
            with self.subTest(key_size=len(key) * 4):
                cipher = Blowfish()
                cipher.generate_keys(bytes.fromhex(key))
                got = cipher.encrypt_block(
                    bytes.fromhex(BLOWFISH_SET_KEY_PT))
                self.assertEqual(got, bytes.fromhex(ct))


class BlowfishRoundTripTestCase(unittest.TestCase):
    """Multi-block round trips and padding."""

    KEY = "0123456789abcdef"

    def test_ecb_round_trip(self):
        """Encrypt changes the data and decrypt restores it exactly."""
        cipher = Blowfish()
        cipher.generate_keys(bytes.fromhex(self.KEY))
        pt = bytes(0xA5 + i for i in range(24))
        ct = cipher.encrypt(pt, mode="ECB")
        self.assertNotEqual(ct, pt)
        self.assertEqual(cipher.decrypt(ct, mode="ECB"), pt)

    def test_cbc_round_trip(self):
        """CBC round trip with an explicit IV."""
        cipher = Blowfish()
        cipher.generate_keys(bytes.fromhex(self.KEY))
        pt = bytes(0x30 + i for i in range(16))
        iv = bytes.fromhex("1122334455667788")
        ct = cipher.encrypt(pt, mode="CBC", iv=iv)
        self.assertNotEqual(ct, pt)
        self.assertEqual(cipher.decrypt(ct, mode="CBC", iv=iv), pt)

    def test_pkcs7_padding(self):
        """A partial block is padded up to one full block and recovered."""
        cipher = Blowfish()
        cipher.generate_keys(bytes.fromhex("AABB09182736CCDD"))
        pt = b"Blowfis"
        ct = cipher.encrypt(pt, mode="ECB", padding="PKCS")
        self.assertEqual(len(ct), 8)
        self.assertEqual(cipher.decrypt(ct, mode="ECB", padding="PKCS"), pt)


if __name__ == "__main__":
    unittest.main()
