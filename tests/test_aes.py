"""Unit tests for AES: FIPS-197 and NIST SP 800-38A known-answer vectors."""

import unittest

from src.AES import AES
from tests.vectors import (AES_FIPS, AES_SP800_CBC, AES_SP800_ECB,
                           AES_SP800_IV, AES_SP800_PT)


class AESKATTestCase(unittest.TestCase):
    """Single-block vectors from FIPS-197 appendix C."""

    def test_fips_197_encrypt(self):
        """Encrypt the FIPS-197 single-block vector for each key size."""
        for name, key, pt, ct in AES_FIPS:
            with self.subTest(cipher=name):
                cipher = AES()
                cipher.generate_keys(bytes.fromhex(key))
                self.assertEqual(cipher.encrypt_block(bytes.fromhex(pt)).hex(),
                                 ct)

    def test_fips_197_decrypt(self):
        """Decrypt the FIPS-197 single-block vector for each key size."""
        for name, key, pt, ct in AES_FIPS:
            with self.subTest(cipher=name):
                cipher = AES()
                cipher.generate_keys(bytes.fromhex(key))
                self.assertEqual(
                    cipher.decrypt_block(bytes.fromhex(ct)).hex(), pt)


class AESModeKATTestCase(unittest.TestCase):
    """Four-block mode vectors from NIST SP 800-38A."""

    def check_mode(self, vectors, mode):
        """Run the four-block SP 800-38A vectors through ``mode``."""
        for name, key, ct in vectors:
            with self.subTest(cipher=name, mode=mode):
                cipher = AES()
                cipher.generate_keys(bytes.fromhex(key))
                iv = bytes.fromhex(AES_SP800_IV) if mode != "ECB" else b""
                plaintext = bytes.fromhex(AES_SP800_PT)
                got = cipher.encrypt(plaintext, mode=mode, padding="", iv=iv)
                self.assertEqual(got.hex(), ct)
                back = cipher.decrypt(bytes.fromhex(ct), mode=mode,
                                      padding="", iv=iv)
                self.assertEqual(back.hex(), AES_SP800_PT)

    def test_sp800_38a_ecb(self):
        """ECB matches SP 800-38A F.1.1/F.1.2/F.1.3."""
        self.check_mode(AES_SP800_ECB, "ECB")

    def test_sp800_38a_cbc(self):
        """CBC matches SP 800-38A F.2.1/F.2.2/F.2.3."""
        self.check_mode(AES_SP800_CBC, "CBC")


class AESRoundTripTestCase(unittest.TestCase):
    """Two-block round trip through ECB for every key size."""

    KEYS = (
        ("AES-128", "000102030405060708090a0b0c0d0e0f"),
        ("AES-192", "000102030405060708090a0b0c0d0e0f1011121314151617"),
        ("AES-256", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"),
    )

    def test_ecb_round_trip(self):
        """Encrypt changes the data and decrypt restores it exactly."""
        for name, key in self.KEYS:
            with self.subTest(cipher=name):
                cipher = AES()
                cipher.generate_keys(bytes.fromhex(key))
                pt = bytes(0xA5 + i for i in range(32))
                ct = cipher.encrypt(pt, mode="ECB")
                self.assertNotEqual(ct, pt)
                self.assertEqual(cipher.decrypt(ct, mode="ECB"), pt)


if __name__ == "__main__":
    unittest.main()
