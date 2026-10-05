"""Unit tests for Serpent against the official NESSIE/verified vectors.

The vector sets (sets 1-4, 128/192/256-bit keys) are as published by
Biham et al., in the standard little-endian octet order that GNU nettle uses.

Where a single-block vector does not exist for a property being tested, the
expected value was produced by GNU nettle and is labelled as such. Serpent's
published material only specifies single-block ECB, so the mode vectors below
are oracle-derived rather than traceable to a numbered table.
"""

import random
import unittest

from src.Serpent import SBOXES, Serpent
from tests.vectors import SERPENT_KATS

# Two-block ECB and one CBC vector per key size, all produced by GNU nettle.
# Distinct plaintext blocks, so a mode that chains where ECB must not shows up.
TWO_BLOCK_PT = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
ECB_TWO_BLOCK = (
    ("128-bit", "000102030405060708090a0b0c0d0e0f",
     "4c7d8a328072a22c823e4a1f3acda16d1fe31aba9824fb1b33b42582291388db"),
    ("192-bit", "000102030405060708090a0b0c0d0e0f1011121314151617",
     "753d5b42d86672fb29070c4fe4eaaf4c4cc221270d91e743ca7b9d9e4e1ebe65"),
    ("256-bit",
     "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
     "de269ff833e432b85b2e88d2701ce75ce534b936d9df2fc053bee5ed268fc68c"),
)
CBC_TWO_BLOCK = (
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    "2aa5a2ff0c27a0f9590f6167e9e779d861fc6463d2e956091e91677d4f38860c",
)


class SerpentSBoxTableTestCase(unittest.TestCase):
    """The embedded S-box tables are the permutations the paper specifies."""

    def test_every_box_is_a_permutation(self):
        """All eight S-boxes map 0..15 onto 0..15 with no repeats, either way.

        Serpent's S-boxes are 4-bit permutations, so a duplicated or dropped
        entry in a table would make it a non-invertible map -- which the
        forward/inverse round trip would not catch, since both directions would
        fail identically.
        """
        for d, boxes in enumerate(SBOXES):
            for n, table in enumerate(boxes):
                with self.subTest(direction=d, box=n):
                    self.assertEqual(sorted(table), list(range(16)))

    def test_inverse_tables_are_the_inverse_permutations(self):
        """The d=1 tables undo the d=0 tables, which is how the paper defines them."""
        for n in range(8):
            with self.subTest(box=n):
                forward = SBOXES[0][n]
                backward = SBOXES[1][n]
                for value, produced in enumerate(forward):
                    self.assertEqual(backward[produced], value)


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


class SerpentWordOrderTestCase(unittest.TestCase):
    """The block and key words are the paper's, in little-endian bit order."""

    def setUp(self):
        """Seed a reproducible generator and build a fresh cipher."""
        self.rng = random.Random(2)
        self.cipher = Serpent()

    def test_schedule_produces_33_round_subkeys(self):
        """One subkey per round plus the final whitening key, for every size."""
        for size in (16, 24, 32):
            with self.subTest(key_size=size):
                cipher = Serpent()
                cipher.generate_keys(bytes(size))
                self.assertEqual(len(cipher.subkeys), 33)

    def test_subkeys_follow_the_paper_word_order(self):
        """Subkey 0 for the all-zero 256-bit key, in the paper's word order.

        This is a regression pin, not a published vector: no numbered table
        lists intermediate subkeys. It is nonetheless fully determined -- the
        16 official ciphertexts in SerpentKATTestCase already pin this
        schedule, because any error in it changes the ciphertext -- so this
        test only has to catch a drift back to the bit-reversed convention.
        It pins the whole convention at once: little-endian loading of the
        block and key words, the un-reversed golden-ratio constant and the
        un-reversed round counter.
        """
        self.cipher.generate_keys(bytes(32))
        self.assertEqual(self.cipher.subkeys[0],
                         [0x6F5795D0, 0xA7E3A3CE, 0xF2D998ED, 0x8ED77390])

    def test_lt_and_its_inverse_are_inverse(self):
        """lt undone by lt_inverse, so both rotate opposite ways."""
        x0 = [self.rng.getrandbits(32) for _ in range(4)]
        self.assertEqual(self.cipher.lt_inverse(self.cipher.lt(list(x0))), x0)


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

    def test_table_and_gate_paths_agree_on_every_vector(self):
        """use_alt=False reproduces every official vector, not just the S-box.

        The S-box level cross-check above only proves the two implementations
        agree; this runs the whole cipher through the bit-sliced table path so
        a difference in how the two are wired into the rounds would also show.
        """
        for name, key, pt, ct in SERPENT_KATS:
            for use_alt in (True, False):
                with self.subTest(vector=name, use_alt=use_alt):
                    cipher = Serpent(use_alt=use_alt)
                    cipher.generate_keys(bytes.fromhex(key))
                    self.assertEqual(cipher.encrypt_block(bytes.fromhex(pt)),
                                     bytes.fromhex(ct))
                    self.assertEqual(cipher.decrypt_block(bytes.fromhex(ct)),
                                     bytes.fromhex(pt))


class SerpentModeKATTestCase(unittest.TestCase):
    """Multi-block mode vectors, produced by GNU nettle.

    Serpent's published vectors are single-block ECB, so nothing published
    covers the mode wrappers or multi-block chaining. These pin the parts of
    the API the official vectors never reach.
    """

    def test_ecb_two_blocks(self):
        """Two distinct plaintext blocks encrypt independently, per key size."""
        for name, key, ct in ECB_TWO_BLOCK:
            with self.subTest(key_size=name):
                cipher = Serpent()
                cipher.generate_keys(bytes.fromhex(key))
                pt = bytes.fromhex(TWO_BLOCK_PT)
                self.assertEqual(cipher.encrypt(pt, mode="ECB",
                                               padding="None").hex(), ct)
                # ECB must not chain: block 2 is E(P2), not E(P2 ^ C1).
                self.assertEqual(cipher.encrypt(pt[16:], mode="ECB",
                                               padding="None").hex(), ct[32:])

    def test_ecb_two_blocks_decrypt(self):
        """Decrypting the published two-block ciphertext recovers the plaintext."""
        for name, key, ct in ECB_TWO_BLOCK:
            with self.subTest(key_size=name):
                cipher = Serpent()
                cipher.generate_keys(bytes.fromhex(key))
                self.assertEqual(cipher.decrypt(bytes.fromhex(ct), mode="ECB",
                                                padding="None"),
                                 bytes.fromhex(TWO_BLOCK_PT))

    def test_cbc_two_blocks(self):
        """CBC chains, so the two ciphertext blocks must differ."""
        key, iv, ct = CBC_TWO_BLOCK
        cipher = Serpent()
        cipher.generate_keys(bytes.fromhex(key))
        self.assertEqual(cipher.encrypt(bytes.fromhex(TWO_BLOCK_PT), mode="CBC",
                                        padding="None",
                                        iv=bytes.fromhex(iv)).hex(), ct)
        self.assertNotEqual(ct[:32], ct[32:])

    def test_cbc_two_blocks_decrypt(self):
        """Decrypting the published CBC ciphertext recovers the plaintext."""
        key, iv, ct = CBC_TWO_BLOCK
        cipher = Serpent()
        cipher.generate_keys(bytes.fromhex(key))
        self.assertEqual(cipher.decrypt(bytes.fromhex(ct), mode="CBC",
                                        padding="None",
                                        iv=bytes.fromhex(iv)),
                         bytes.fromhex(TWO_BLOCK_PT))

    def test_cbc_first_block_is_plaintext_xor_iv(self):
        """CBC is ECB of (P0 ^ IV) for the first block, pinned to a real value."""
        key, iv, ct = CBC_TWO_BLOCK
        ecb = Serpent()
        ecb.generate_keys(bytes.fromhex(key))
        first = bytes(a ^ b for a, b in zip(bytes.fromhex(TWO_BLOCK_PT)[:16],
                                            bytes.fromhex(iv)))
        self.assertEqual(ecb.encrypt_block(first).hex(), ct[:32])


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


class SerpentArgumentTestCase(unittest.TestCase):
    """Bad key and block sizes are rejected rather than silently absorbed.

    Note this is a deliberate difference from the C, C++ and Java ports, which
    accept any key length and pad short ones with a 0x01 byte per the spec.
    Python rejects instead, consistently across all five ciphers here.
    """

    def test_valid_key_sizes_are_accepted(self):
        """16, 24 and 32 byte keys all produce a usable schedule."""
        for size in (16, 24, 32):
            with self.subTest(key_size=size):
                cipher = Serpent()
                cipher.generate_keys(bytes(size))
                self.assertEqual(len(cipher.subkeys), 33)

    def test_invalid_key_sizes_are_rejected(self):
        """Anything that is not 16, 24 or 32 bytes raises, including short keys."""
        for size in (0, 1, 15, 17, 20, 31, 33, 64):
            with self.subTest(key_size=size):
                with self.assertRaises(ValueError):
                    Serpent().generate_keys(bytes(size))

    def test_non_block_sized_plaintext_is_rejected(self):
        """encrypt_block and decrypt_block want exactly 16 bytes."""
        cipher = Serpent()
        cipher.generate_keys(bytes(16))
        for size in (0, 8, 15, 17, 32):
            with self.subTest(plaintext_size=size):
                with self.assertRaises(ValueError):
                    cipher.encrypt_block(bytes(size))
                with self.assertRaises(ValueError):
                    cipher.decrypt_block(bytes(size))


if __name__ == "__main__":
    unittest.main()
