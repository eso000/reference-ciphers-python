"""Smoke tests: every cipher reproduces its headline vector.

One vector per cipher, straight from the specification it implements, so a
broken import or a refactor that garbles a round key fails loudly and fast.
"""

import unittest

from src.AES import AES
from src.Blowfish import Blowfish
from src.DES import DES, TripleDES
from src.Serpent import Serpent
from src.Twofish import Twofish
from tests.vectors import SMOKE_VECTORS

CIPHER_CLASSES = {
    "AES": AES,
    "Blowfish": Blowfish,
    "DES": DES,
    "3DES": TripleDES,
    "Serpent": Serpent,
    "Twofish": Twofish,
}


class SmokeTestCase(unittest.TestCase):
    """Each cipher encrypts to its published vector and decrypts back."""

    def test_canonical_vector(self):
        """Encrypt to the published vector, then recover the plaintext."""
        for name, key, pt, ct in SMOKE_VECTORS:
            with self.subTest(cipher=name):
                cipher = CIPHER_CLASSES[name]()
                cipher.generate_keys(bytes.fromhex(key))
                plaintext = bytes.fromhex(pt)
                got = cipher.encrypt_block(plaintext)
                self.assertEqual(got, bytes.fromhex(ct))
                self.assertEqual(cipher.decrypt_block(got), plaintext)


if __name__ == "__main__":
    unittest.main()
