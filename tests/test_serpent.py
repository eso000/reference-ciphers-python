"""Unit tests for Serpent against the official NESSIE/verified vectors.

The vector sets (sets 1-4, 128/192/256-bit keys) are as published by
Biham et al., in the standard little-endian octet order that GNU nettle uses.
The tests also cross-check the two S-box implementations: the word-sliced
gate network (apply_sbox, the default) and the bit-sliced table path
(apply_sbox_bit, use_alt=False) must agree, and the SBOXES appendix must
hold the 4-bit permutations the paper specifies.
"""
import random
import unittest

from src.Serpent import SBOXES, Serpent
from tests import cipher_test_base as base
from tests.vectors import SERPENT_KATS


class SerpentKATTestCase(base.BlockKATTestMixin):
    """NESSIE/verified single-block vectors on the default gate-network path."""
    CipherClass = Serpent
    BLOCK_KATS = SERPENT_KATS

    def test_table_path_reproduces_vectors(self):
        """The bit-sliced table path (use_alt=False) reproduces every vector.

        The mixin KATs above only exercise the default word-sliced gate
        network. Running the whole cipher through the alternative bit-sliced
        path proves the two S-box implementations are wired into the rounds
        identically, not just that they agree in isolation.
        """
        for name, key_hex, pt_hex, ct_hex in SERPENT_KATS:
            with self.subTest(vector=name):
                cipher = Serpent(use_alt=False)
                cipher.generate_keys(bytes.fromhex(key_hex))
                self.assertEqual(
                    cipher.encrypt_block(bytes.fromhex(pt_hex)),
                    bytes.fromhex(ct_hex))
                self.assertEqual(
                    cipher.decrypt_block(bytes.fromhex(ct_hex)),
                    bytes.fromhex(pt_hex))


class SerpentSBoxTestCase(unittest.TestCase):
    """The embedded S-box tables and the two implementations agree.

    The agreement tests are randomized but seeded, so a failure reproduces.
    """

    RANDOM_WORDS = 200

    def setUp(self):
        """Seed a reproducible generator for the agreement tests."""
        self.rng = random.Random(1)

    def random_words(self):
        """Return four random 32-bit words."""
        return [self.rng.getrandbits(32) for _ in range(4)]

    def test_every_box_is_a_permutation(self):
        """All eight S-boxes map 0..15 onto 0..15 with no repeats, either way.

        Serpent's S-boxes are 4-bit permutations, so a duplicated or dropped
        entry would make a table non-invertible -- which a forward/inverse
        round trip would not catch, since both directions would fail
        identically.
        """
        for direction, boxes in enumerate(SBOXES):
            for box, table in enumerate(boxes):
                with self.subTest(direction=direction, box=box):
                    self.assertEqual(sorted(table), list(range(16)))

    def test_inverse_tables_are_the_inverse_permutations(self):
        """The d=1 tables undo the d=0 tables, as the paper defines them."""
        for box in range(8):
            with self.subTest(box=box):
                forward = SBOXES[0][box]
                backward = SBOXES[1][box]
                for value, produced in enumerate(forward):
                    self.assertEqual(backward[produced], value)

    def test_gate_matches_table_forward(self):
        """apply_sbox agrees with apply_sbox_bit in the forward direction."""
        cipher = Serpent()
        for _ in range(self.RANDOM_WORDS):
            words = self.random_words()
            for box in range(8):
                with self.subTest(box=box, words=words):
                    self.assertEqual(cipher.apply_sbox(list(words), box, d=0),
                                     cipher.apply_sbox_bit(list(words), box, d=0))

    def test_gate_matches_table_inverse(self):
        """apply_sbox agrees with apply_sbox_bit in the inverse direction."""
        cipher = Serpent()
        for _ in range(self.RANDOM_WORDS):
            words = self.random_words()
            for box in range(8):
                with self.subTest(box=box, words=words):
                    self.assertEqual(cipher.apply_sbox(list(words), box, d=1),
                                     cipher.apply_sbox_bit(list(words), box, d=1))

    def test_inverse_is_inverse_of_forward(self):
        """Applying the table path forward then inverse is the identity."""
        cipher = Serpent()
        for _ in range(self.RANDOM_WORDS):
            words = self.random_words()
            for box in range(8):
                with self.subTest(box=box, words=words):
                    once = cipher.apply_sbox_bit(list(words), box, d=0)
                    back = cipher.apply_sbox_bit(once, box, d=1)
                    self.assertEqual(back, words)


if __name__ == "__main__":
    unittest.main()
