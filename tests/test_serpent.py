"""Unit tests for Serpent against the official NESSIE/verified vectors.

The vector sets (sets 1-4, 128/192/256-bit keys) are as published by
Biham et al., in the standard little-endian octet order that GNU nettle uses.
"""

import random
import unittest

from src.Serpent import Serpent
from tests.vectors import SERPENT_KATS


class SerpentSBoxTestCase(unittest.TestCase):
    """The gate network and the bit-sliced table must be the same function."""

    RANDOM_WORDS = 200

    def setUp(self):
        """Seed a reproducible generator and build a fresh cipher."""
        self.rng = random.Random(1)
        self.cipher = Serpent()

    def random_words(self):
        """Return four random 32-bit words."""
        return [self.rng.getrandbits(32) for _ in range(4)]

    def test_gate_matches_table_forward(self):
        """apply_sbox agrees with apply_sbox_bit in the forward direction."""
        for _ in range(self.RANDOM_WORDS):
            x = self.random_words()
            for n in range(8):
                with self.subTest(box=n, words=x):
                    self.assertEqual(self.cipher.apply_sbox(list(x), n, d=0),
                                     self.cipher.apply_sbox_bit(list(x), n, d=0))

    def test_gate_matches_table_inverse(self):
        """apply_sbox agrees with apply_sbox_bit in the inverse direction."""
        for _ in range(self.RANDOM_WORDS):
            x = self.random_words()
            for n in range(8):
                with self.subTest(box=n, words=x):
                    self.assertEqual(self.cipher.apply_sbox(list(x), n, d=1),
                                     self.cipher.apply_sbox_bit(list(x), n, d=1))

    def test_inverse_is_inverse_of_forward(self):
        """Applying the table forward then inverse is the identity."""
        for _ in range(self.RANDOM_WORDS):
            x0 = self.random_words()
            for n in range(8):
                with self.subTest(box=n, words=x0):
                    once = self.cipher.apply_sbox_bit(list(x0), n, d=0)
                    back = self.cipher.apply_sbox_bit(once, n, d=1)
                    self.assertEqual(back, x0)


class SerpentKATTestCase(unittest.TestCase):
    """The 16 official single-block vectors."""

    def test_encrypt(self):
        """Encrypt every official vector."""
        for name, key, pt, ct in SERPENT_KATS:
            with self.subTest(vector=name):
                cipher = Serpent()
                cipher.generate_keys(bytes.fromhex(key))
                self.assertEqual(cipher.encrypt_block(bytes.fromhex(pt)),
                                 bytes.fromhex(ct))

    def test_decrypt(self):
        """Decrypt every official vector."""
        for name, key, pt, ct in SERPENT_KATS:
            with self.subTest(vector=name):
                cipher = Serpent()
                cipher.generate_keys(bytes.fromhex(key))
                self.assertEqual(cipher.decrypt_block(bytes.fromhex(ct)),
                                 bytes.fromhex(pt))


class SerpentRoundTripTestCase(unittest.TestCase):
    """Multi-block round trips and padding."""

    KEYS = (
        ("128-bit", "80000000000000000000000000000000"),
        ("192-bit", "800000000000000000000000000000000000000000000000"),
        ("256-bit", "8000000000000000000000000000000000000000000000000000000000000000"),
    )

    def test_ecb_round_trip_all_key_sizes(self):
        """Two blocks round trip through ECB for 128/192/256-bit keys."""
        for name, key in self.KEYS:
            with self.subTest(key_size=name):
                cipher = Serpent()
                cipher.generate_keys(bytes.fromhex(key))
                pt = bytes(0xA5 + i for i in range(32))
                ct = cipher.encrypt(pt, mode="ECB")
                self.assertNotEqual(ct, pt)
                self.assertEqual(cipher.decrypt(ct, mode="ECB"), pt)

    def test_cbc_round_trip(self):
        """Two blocks round trip through CBC with an explicit IV."""
        cipher = Serpent()
        cipher.generate_keys(bytes.fromhex("0123456789abcdef0123456789abcdef"))
        pt = bytes(range(32))
        iv = b"\xbb" * 16
        ct = cipher.encrypt(pt, mode="CBC", iv=iv)
        self.assertNotEqual(ct, pt)
        self.assertEqual(cipher.decrypt(ct, mode="CBC", iv=iv), pt)

    def test_pkcs7_padding(self):
        """A partial block is padded up to one full block and recovered."""
        cipher = Serpent()
        cipher.generate_keys(bytes.fromhex("000102030405060708090a0b0c0d0e0f"))
        pt = b"serpent"
        ct = cipher.encrypt(pt, mode="ECB", padding="PKCS")
        self.assertEqual(len(ct), 16)
        self.assertEqual(cipher.decrypt(ct, mode="ECB", padding="PKCS"), pt)


if __name__ == "__main__":
    unittest.main()
