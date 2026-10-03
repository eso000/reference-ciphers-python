"""Unit tests for the shared block-mode scaffolding in EncryptionBase.

Covers the padding schemes in isolation (including malformed input) and the
helpers the ciphers inherit, without needing a specific cipher.
"""

import unittest

from src.encryption_base import EncryptionBase


class DummyCipher(EncryptionBase):
    """Minimal concrete cipher so the base class can be exercised directly."""

    block_size = 8


class PermutationHelperTestCase(unittest.TestCase):
    """bitwise_xor_bytes, permutate_int, rotl and rotr."""

    def test_bitwise_xor_bytes(self):
        """XOR pairs corresponding bytes up to the shorter length."""
        self.assertEqual(
            DummyCipher.bitwise_xor_bytes(b"\x0f\xf0", b"\xff\xff"),
            b"\xf0\x0f")

    def test_bitwise_xor_bytes_stops_at_shorter(self):
        """A length mismatch truncates rather than raising."""
        self.assertEqual(
            DummyCipher.bitwise_xor_bytes(b"\x01\x02\x03", b"\x01"),
            b"\x00")

    def test_permutate_int(self):
        """Bits are picked out in the order the table lists them.

        Index 1 is the most significant bit of the input and the first entry in
        ``perm`` becomes the most significant bit of the output.
        """
        # Index 1 is the most significant input bit.
        self.assertEqual(DummyCipher.permutate_int(0xA0, [1, 2], 8), 0b10)
        # Index 8 is the least significant input bit (0 for 0xA0).
        self.assertEqual(DummyCipher.permutate_int(0xA0, [8, 7], 8), 0b00)
        # The table order decides the output order, so swapping swaps the bits.
        self.assertEqual(DummyCipher.permutate_int(0xA0, [2, 1], 8), 0b01)
        # Narrowing the width shifts which input bit index 1 refers to.
        self.assertEqual(DummyCipher.permutate_int(0b11, [1, 2], 2), 0b11)

    def test_permutate_int_identity_table(self):
        """Listing bits most-significant first is the identity."""
        self.assertEqual(DummyCipher.permutate_int(0xA5, [1, 2, 3, 4, 5, 6, 7, 8],
                                                   8), 0xA5)

    def test_rotl(self):
        """rotl wraps bits around within the given width."""
        self.assertEqual(DummyCipher.rotl(0b1000_0001, 1, 8), 0b0000_0011)

    def test_rotr(self):
        """rotr is the inverse of rotl."""
        self.assertEqual(DummyCipher.rotr(0b0000_0011, 1, 8), 0b1000_0001)

    def test_rotations_by_zero_are_identity(self):
        """A zero shift (or a full-width shift) leaves the value alone."""
        self.assertEqual(DummyCipher.rotl(0xA5, 0, 8), 0xA5)
        self.assertEqual(DummyCipher.rotr(0xA5, 8, 8), 0xA5)


class ModePaddingPredicateTestCase(unittest.TestCase):
    """mode_needs_padding splits block modes from keystream modes."""

    def test_block_modes_need_padding(self):
        """ECB, CBC and PCBC only work on whole blocks."""
        for mode in ("ECB", "CBC", "PCBC"):
            with self.subTest(mode=mode):
                self.assertTrue(DummyCipher.mode_needs_padding(mode))

    def test_stream_modes_do_not_need_padding(self):
        """CFB, OFB and CTR truncate the keystream instead."""
        for mode in ("CFB", "OFB", "CTR"):
            with self.subTest(mode=mode):
                self.assertFalse(DummyCipher.mode_needs_padding(mode))

    def test_unknown_mode_rejected(self):
        """An unrecognised mode name is an error, not a default."""
        with self.assertRaises(ValueError):
            DummyCipher.mode_needs_padding("GCM")


class PadUnpadRoundTripTestCase(unittest.TestCase):
    """Every reversible scheme round trips at every length around a block."""

    SCHEMES = ("PKCS", "ANSI X9.23", "ISO 7816-4", "bit", "TBC")
    LENGTHS = (0, 1, 7, 8, 9, 16)

    def setUp(self):
        """Build a cipher to pad with."""
        self.cipher = DummyCipher()

    def pad(self, data, scheme, mode="CBC"):
        """Pad ``data`` for ``scheme`` under ``mode``."""
        return self.cipher.pad_for_mode(data, self.cipher.block_size,
                                        mode, scheme)

    def unpad(self, data, scheme, mode="CBC"):
        """Remove ``scheme`` padding from ``data``."""
        return self.cipher.unpad_for_mode(data, self.cipher.block_size,
                                          mode, scheme)

    def test_reversible_schemes_round_trip(self):
        """Each scheme pads to the next boundary and comes back intact."""
        for scheme in self.SCHEMES:
            for length in self.LENGTHS:
                with self.subTest(scheme=scheme, length=length):
                    pt = bytes(range(length))
                    padded = self.pad(pt, scheme)
                    self.assertEqual(len(padded) % self.cipher.block_size, 0)
                    self.assertEqual(len(padded) > len(pt), True)
                    self.assertEqual(self.unpad(padded, scheme), pt)

    def test_block_aligned_input_still_gains_a_block(self):
        """An aligned message gets a whole extra block so it stays unambiguous."""
        for scheme in self.SCHEMES:
            with self.subTest(scheme=scheme):
                pt = bytes(self.cipher.block_size)
                padded = self.pad(pt, scheme)
                self.assertEqual(len(padded), 2 * self.cipher.block_size)
                self.assertEqual(self.unpad(padded, scheme), pt)

    def test_no_padding_requires_aligned_input(self):
        """With padding="" a partial block is rejected."""
        with self.assertRaises(ValueError):
            self.pad(b"abc", "")

    def test_no_padding_passes_aligned_input_through(self):
        """With padding="" an aligned message is returned unchanged."""
        pt = bytes(self.cipher.block_size)
        self.assertEqual(self.pad(pt, ""), pt)

    def test_zero_padding_fills_to_boundary(self):
        """Zero padding only fills to the boundary and is not reversible."""
        padded = self.pad(b"abc", "0")
        self.assertEqual(len(padded), self.cipher.block_size)
        self.assertEqual(self.unpad(padded, "0"), padded)

    def test_zero_padding_of_aligned_input_adds_nothing(self):
        """Zero padding of an aligned message is a no-op."""
        pt = bytes(self.cipher.block_size)
        self.assertEqual(self.pad(pt, "0"), pt)

    def test_unknown_scheme_rejected(self):
        """An unrecognised padding name is an error."""
        with self.assertRaises(ValueError):
            self.pad(b"abc", "ROT13")

    def test_stream_modes_never_pad(self):
        """Keystream modes return the data untouched whatever the scheme."""
        for scheme in self.SCHEMES + ("", "0"):
            with self.subTest(scheme=scheme):
                pt = b"abc"
                self.assertEqual(self.pad(pt, scheme, mode="CTR"), pt)
                self.assertEqual(self.unpad(pt, scheme, mode="CTR"), pt)


class MalformedPaddingTestCase(unittest.TestCase):
    """Bad padding must raise rather than silently truncate."""

    def setUp(self):
        """Build a cipher and a full block of known data."""
        self.cipher = DummyCipher()
        self.block = bytes(range(self.cipher.block_size))

    def unpad(self, data, scheme):
        """Remove ``scheme`` padding from ``data``."""
        return self.cipher.unpad_for_mode(data, self.cipher.block_size,
                                          "CBC", scheme)

    def test_pkcs_count_out_of_range(self):
        """A padding byte larger than the block is invalid."""
        with self.assertRaises(ValueError):
            self.unpad(bytes([self.cipher.block_size + 1]) + self.block,
                       "PKCS")

    def test_pkcs_zero_count(self):
        """A padding count of zero is invalid."""
        with self.assertRaises(ValueError):
            self.unpad(b"\x00" * self.cipher.block_size, "PKCS")

    def test_pkcs_inconsistent_filler(self):
        """PKCS#7 filler bytes must all equal the count."""
        with self.assertRaises(ValueError):
            self.unpad(b"\x03\x03\x02", "PKCS")

    def test_ansi_x9_23_nonzero_body(self):
        """ANSI X9.23 filler before the count must be zero."""
        with self.assertRaises(ValueError):
            self.unpad(b"\x01\x02\x03", "ANSI X9.23")

    def test_iso_7816_4_missing_marker(self):
        """ISO 7816-4 padding must end with 0x80 after zeros."""
        with self.assertRaises(ValueError):
            self.unpad(b"\x00" * self.cipher.block_size, "ISO 7816-4")

    def test_tbc_invalid_final_byte(self):
        """TBC padding must end with 0x00 or 0xFF."""
        with self.assertRaises(ValueError):
            self.unpad(bytes(range(self.cipher.block_size)), "TBC")

    def test_unknown_scheme_rejected(self):
        """An unrecognised padding name is an error on unpad too."""
        with self.assertRaises(ValueError):
            self.unpad(self.block, "ROT13")


class TypeAndLengthGuardTestCase(unittest.TestCase):
    """str is rejected outright and hex is never guessed."""

    def test_as_bytes_rejects_str(self):
        """_as_bytes refuses str rather than parsing it as hex."""
        with self.assertRaises(TypeError):
            DummyCipher._as_bytes("00ff", "block")

    def test_as_bytes_accepts_bytearray(self):
        """bytearray is accepted and normalised to bytes."""
        self.assertEqual(DummyCipher._as_bytes(bytearray(b"ab"), "block"),
                         b"ab")

    def test_checked_key_enforces_length(self):
        """_checked_key accepts only the listed sizes."""
        self.assertEqual(DummyCipher._checked_key(bytes(8), (8,), "test"), bytes(8))
        with self.assertRaises(ValueError):
            DummyCipher._checked_key(bytes(7), (8,), "test")

    def test_checked_key_rejects_str(self):
        """A str key is a TypeError, not a ValueError."""
        with self.assertRaises(TypeError):
            DummyCipher._checked_key("00" * 8, (8,), "test")

    def test_checked_block_enforces_one_block(self):
        """_checked_block accepts exactly block_size bytes."""
        cipher = DummyCipher()
        self.assertEqual(cipher._checked_block(bytes(8)), bytes(8))
        for n in (0, 7, 9):
            with self.subTest(size=n):
                with self.assertRaises(ValueError):
                    cipher._checked_block(bytes(n))

    def test_placeholder_block_methods_pass_through(self):
        """The base class block methods are pass-through placeholders."""
        cipher = DummyCipher()
        self.assertEqual(cipher.encrypt_block(b"12345678"), b"12345678")
        self.assertEqual(cipher.decrypt_block(b"12345678"), b"12345678")


if __name__ == "__main__":
    unittest.main()
