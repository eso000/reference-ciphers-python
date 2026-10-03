"""Unit tests for Twofish against the official submission KATs.

Vectors: the official Twofish KATs (Schneier et al., B.2) for 128/192/256-bit
keys; the 128 chain continues the all-zero ciphertext as the next plaintext.
"""

import unittest

from src.Twofish import Twofish
from tests.vectors import TWOFISH_KATS


class TwofishKATTestCase(unittest.TestCase):
    """The five official single-block vectors."""

    def test_encrypt(self):
        """Encrypt every official vector."""
        for i, (key, pt, ct) in enumerate(TWOFISH_KATS):
            with self.subTest(vector=f"kat {i + 1:02d}"):
                cipher = Twofish()
                cipher.generate_keys(bytes.fromhex(key))
                self.assertEqual(cipher.encrypt_block(bytes.fromhex(pt)),
                                 bytes.fromhex(ct))

    def test_decrypt(self):
        """Decrypt every official vector."""
        for i, (key, pt, ct) in enumerate(TWOFISH_KATS):
            with self.subTest(vector=f"kat {i + 1:02d}"):
                cipher = Twofish()
                cipher.generate_keys(bytes.fromhex(key))
                self.assertEqual(cipher.decrypt_block(bytes.fromhex(ct)),
                                 bytes.fromhex(pt))


class TwofishRoundTripTestCase(unittest.TestCase):
    """Multi-block round trips and padding."""

    KEYS = (
        ("128-bit", "000102030405060708090a0b0c0d0e0f"),
        ("192-bit", "000102030405060708090a0b0c0d0e0f1011121314151617"),
        ("256-bit",
         "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"),
    )

    def test_ecb_round_trip_all_key_sizes(self):
        """Two blocks round trip through ECB for 128/192/256-bit keys."""
        for name, key in self.KEYS:
            with self.subTest(key_size=name):
                cipher = Twofish()
                cipher.generate_keys(bytes.fromhex(key))
                pt = bytes(0xA5 + i for i in range(32))
                ct = cipher.encrypt(pt, mode="ECB")
                self.assertNotEqual(ct, pt)
                self.assertEqual(cipher.decrypt(ct, mode="ECB"), pt)

    def test_cbc_round_trip(self):
        """Two blocks round trip through CBC with an explicit IV."""
        cipher = Twofish()
        cipher.generate_keys(bytes.fromhex("0123456789abcdef0123456789abcdef"))
        pt = bytes(range(32))
        iv = b"\xaa" * 16
        ct = cipher.encrypt(pt, mode="CBC", iv=iv)
        self.assertNotEqual(ct, pt)
        self.assertEqual(cipher.decrypt(ct, mode="CBC", iv=iv), pt)


class TwofishPaddingTestCase(unittest.TestCase):
    """PKCS#7 padding on 16-byte blocks."""

    def setUp(self):
        """Load a fixed key into a fresh cipher."""
        self.cipher = Twofish()
        self.cipher.generate_keys(
            bytes.fromhex("00112233445566778899aabbccddeeff"))

    def test_partial_block_padded_to_one_block(self):
        """Seven bytes become one block and round trip."""
        pt = bytes.fromhex("123456abcdcd13")
        ct = self.cipher.encrypt(pt, mode="ECB", padding="PKCS")
        self.assertEqual(len(ct), 16)
        self.assertEqual(self.cipher.decrypt(ct, mode="ECB", padding="PKCS"), pt)

    def test_empty_input_padded_to_one_block(self):
        """An empty message still produces one block under PKCS#7."""
        self.assertEqual(len(self.cipher.encrypt(b"", mode="ECB",
                                                 padding="PKCS")), 16)

    def test_unpadded_block_is_not_valid_pkcs(self):
        """A full block of counter values is not valid PKCS#7 padding."""
        ct = self.cipher.encrypt(bytes(range(16)), mode="ECB", padding="")
        with self.assertRaises(ValueError):
            self.cipher.decrypt(ct, mode="ECB", padding="PKCS")


if __name__ == "__main__":
    unittest.main()
