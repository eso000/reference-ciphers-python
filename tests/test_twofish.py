"""Unit tests for Twofish against the official submission KATs.

Vectors: the official Twofish KATs (Schneier et al., B.2) for 128/192/256-bit
keys; the 128 chain continues the all-zero ciphertext as the next plaintext.
"""

import unittest

from src.Twofish import Twofish
from tests import cipher_test_base as base
from tests.vectors import TWOFISH_KATS


class TwofishKATTestCase(base.BlockKATTestMixin):
    """The five official single-block vectors."""

    CipherClass = Twofish
    BLOCK_KATS = TWOFISH_KATS


class TwofishRoundTripTestCase(base.CBCRoundTripTestMixin):
    """Multi-block round trips through ECB and CBC."""

    CipherClass = Twofish
    KEYS = (
        ("128-bit", "000102030405060708090a0b0c0d0e0f"),
        ("192-bit", "000102030405060708090a0b0c0d0e0f1011121314151617"),
        ("256-bit", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"),
    )
    ECB_PT_LEN = 32
    CBC_KEY = "0123456789abcdef0123456789abcdef"
    CBC_IV = "aa" * 16
    CBC_PT_SEED = 0x00
    CBC_PT_LEN = 32


class TwofishPaddingTestCase(unittest.TestCase):
    """PKCS#7 padding on 16-byte blocks."""

    def setUp(self):
        """Load a fixed key into a fresh cipher."""
        self.cipher = Twofish()
        self.cipher.generate_keys(bytes.fromhex("00112233445566778899aabbccddeeff"))

    def test_partial_block_padded_to_one_block(self):
        """Seven bytes become one block and round trip."""
        pt = bytes.fromhex("123456abcdcd13")
        ct = self.cipher.encrypt(pt, mode="ECB", padding="PKCS")
        self.assertEqual(len(ct), 16)
        self.assertEqual(self.cipher.decrypt(ct, mode="ECB", padding="PKCS"), pt)

    def test_empty_input_padded_to_one_block(self):
        """An empty message still produces one block under PKCS#7."""
        self.assertEqual(len(self.cipher.encrypt(b"", mode="ECB", padding="PKCS")), 16)

    def test_unpadded_block_is_not_valid_pkcs(self):
        """A full block of counter values is not valid PKCS#7 padding."""
        ct = self.cipher.encrypt(bytes(range(16)), mode="ECB", padding="")
        with self.assertRaises(ValueError):
            self.cipher.decrypt(ct, mode="ECB", padding="PKCS")


if __name__ == "__main__":
    unittest.main()
