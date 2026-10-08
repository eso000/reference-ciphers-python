"""Unit tests for the shared block-mode scaffolding in EncryptionBase.

Covers the padding schemes in isolation (including malformed input) and the
helpers the ciphers inherit, without needing a specific cipher.
"""

import unittest

from src.encryption_base import EncryptionBase


class DummyCipher(EncryptionBase):
    """Toy 64-bit cipher that uses the base-class helpers as real ciphers do.

    ``generate_keys`` validates the key with ``_checked_key`` and the block
    methods validate their input with ``_checked_block``, so the private guards
    are exercised through the public interface. The transform (XOR with the
    key, then reverse the bytes) is trivially invertible and NOT secure.
    """

    block_size = 8
    key_size = 8

    def __init__(self):
        """Start with no key; call ``generate_keys`` before encrypting."""
        self.key = b""

    def generate_keys(self, key: bytes) -> None:
        """Store ``key`` after checking that it is exactly 8 bytes."""
        self.key = self._checked_key(key, (self.key_size,), "Dummy")

    def encrypt_block(self, plaintext: bytes) -> bytes:
        """XOR one block with the key, then reverse its bytes."""
        block = self._checked_block(plaintext)
        return self.bitwise_xor_bytes(block, self.key)[::-1]

    def decrypt_block(self, ciphertext: bytes) -> bytes:
        """Undo :meth:`encrypt_block`."""
        block = self._checked_block(ciphertext)
        return self.bitwise_xor_bytes(block[::-1], self.key)


class PermutationHelperTestCase(unittest.TestCase):
    """bitwise_xor_bytes, permutate_int, rotl and rotr."""

    def test_bitwise_xor_bytes(self):
        """XOR pairs corresponding bytes up to the shorter length."""
        self.assertEqual(
            DummyCipher.bitwise_xor_bytes(b"\x0f\xf0", b"\xff\xff"), b"\xf0\x0f"
        )

    def test_bitwise_xor_bytes_stops_at_shorter(self):
        """A length mismatch truncates rather than raising."""
        self.assertEqual(
            DummyCipher.bitwise_xor_bytes(b"\x01\x02\x03", b"\x01"), b"\x00"
        )

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
        self.assertEqual(
            DummyCipher.permutate_int(0xA5, [1, 2, 3, 4, 5, 6, 7, 8], 8), 0xA5
        )

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
        return self.cipher.pad_for_mode(data, self.cipher.block_size, mode, scheme)

    def unpad(self, data, scheme, mode="CBC"):
        """Remove ``scheme`` padding from ``data``."""
        return self.cipher.unpad_for_mode(data, self.cipher.block_size, mode, scheme)

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
        return self.cipher.unpad_for_mode(data, self.cipher.block_size, "CBC", scheme)

    def test_pkcs_count_out_of_range(self):
        """A padding byte larger than the block is invalid."""
        with self.assertRaises(ValueError):
            self.unpad(bytes([self.cipher.block_size + 1]) + self.block, "PKCS")

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

    KEY = bytes(range(1, 9))
    BLOCK = b"12345678"

    def setUp(self):
        """Build a keyed cipher."""
        self.cipher = DummyCipher()
        self.cipher.generate_keys(self.KEY)

    def test_key_rejects_str(self):
        """A str key is a TypeError, not a ValueError."""
        with self.assertRaises(TypeError):
            self.cipher.generate_keys("00" * 8)

    def test_key_enforces_length(self):
        """Only the listed key sizes are accepted."""
        for n in (0, 7, 9):
            with self.subTest(size=n):
                with self.assertRaises(ValueError):
                    self.cipher.generate_keys(bytes(n))

    def test_key_accepts_bytearray(self):
        """A bytearray key is normalised to bytes."""
        self.cipher.generate_keys(bytearray(self.KEY))
        self.assertEqual(self.cipher.key, self.KEY)

    def test_block_rejects_str(self):
        """Block methods refuse str rather than parsing it as hex."""
        for method in (self.cipher.encrypt_block, self.cipher.decrypt_block):
            with self.subTest(method=method.__name__):
                with self.assertRaises(TypeError):
                    method("0011223344556677")

    def test_block_enforces_one_block(self):
        """Block methods accept exactly block_size bytes."""
        for method in (self.cipher.encrypt_block, self.cipher.decrypt_block):
            for n in (0, 7, 9):
                with self.subTest(method=method.__name__, size=n):
                    with self.assertRaises(ValueError):
                        method(bytes(n))

    def test_block_accepts_bytearray(self):
        """A bytearray block gives the same result as bytes."""
        self.assertEqual(
            self.cipher.encrypt_block(bytearray(self.BLOCK)),
            self.cipher.encrypt_block(self.BLOCK),
        )

    def test_block_round_trip(self):
        """decrypt_block undoes encrypt_block, and encryption changes the data."""
        encrypted = self.cipher.encrypt_block(self.BLOCK)
        self.assertNotEqual(encrypted, self.BLOCK)
        self.assertEqual(self.cipher.decrypt_block(encrypted), self.BLOCK)

    def test_message_methods_reject_str(self):
        """encrypt and decrypt refuse str for the data and the IV."""
        iv = bytes(8)
        cases = (
            (self.cipher.encrypt, ("abc", "CBC", "PKCS", iv)),
            (self.cipher.encrypt, (b"abc", "CBC", "PKCS", "00" * 8)),
            (self.cipher.decrypt, ("abc", "CBC", "PKCS", iv)),
            (self.cipher.decrypt, (bytes(8), "CBC", "PKCS", "00" * 8)),
        )
        for method, args in cases:
            with self.subTest(method=method.__name__, args=args):
                with self.assertRaises(TypeError):
                    method(*args)

    def test_message_methods_accept_bytearray(self):
        """bytearray data and IV behave exactly like bytes."""
        iv = bytes(range(8))
        expected = self.cipher.encrypt(b"abc", "CBC", "PKCS", iv)
        self.assertEqual(
            self.cipher.encrypt(bytearray(b"abc"), "CBC", "PKCS", bytearray(iv)),
            expected,
        )
        self.assertEqual(
            self.cipher.decrypt(bytearray(expected), "CBC", "PKCS", bytearray(iv)),
            b"abc",
        )


class BlockModeRoundTripTestCase(unittest.TestCase):
    """Every mode round trips through the toy cipher."""

    MODES = ("ECB", "CBC", "PCBC", "CFB", "OFB", "CTR")
    LENGTHS = (0, 1, 7, 8, 9, 20)

    def setUp(self):
        """Build a keyed cipher."""
        self.cipher = DummyCipher()
        self.cipher.generate_keys(bytes(range(1, 9)))

    def test_modes_round_trip(self):
        """decrypt(encrypt(x)) == x for every mode and message length."""
        for mode in self.MODES:
            iv = b"" if mode == "ECB" else bytes(range(8))
            for length in self.LENGTHS:
                with self.subTest(mode=mode, length=length):
                    message = bytes(range(length))
                    encrypted = self.cipher.encrypt(message, mode, "PKCS", iv)
                    self.assertEqual(
                        self.cipher.decrypt(encrypted, mode, "PKCS", iv), message
                    )

    def test_iv_rules(self):
        """ECB rejects an IV; every other mode needs one full block."""
        with self.assertRaises(ValueError):
            self.cipher.encrypt(b"abc", "ECB", "PKCS", bytes(8))
        for mode in self.MODES[1:]:
            with self.subTest(mode=mode):
                with self.assertRaises(ValueError):
                    self.cipher.encrypt(b"abc", mode, "PKCS", b"short")

    def test_unknown_mode_rejected(self):
        """An unrecognised mode is an error in both directions."""
        with self.assertRaises(ValueError):
            self.cipher.encrypt(b"abc", "GCM", "PKCS", bytes(8))
        with self.assertRaises(ValueError):
            self.cipher.decrypt(bytes(8), "GCM", "PKCS", bytes(8))

    def test_partial_block_ciphertext_rejected(self):
        """Block-mode ciphertext must be a whole number of blocks."""
        with self.assertRaises(ValueError):
            self.cipher.decrypt(bytes(9), "CBC", "PKCS", bytes(8))


class BaseClassPlaceholderTestCase(unittest.TestCase):
    """EncryptionBase's own block methods are pass-through placeholders."""

    def test_placeholder_block_methods_pass_through(self):
        """With no cipher behind it, the base class returns its input."""
        base = EncryptionBase()
        self.assertEqual(base.encrypt_block(b"12345678"), b"12345678")
        self.assertEqual(base.decrypt_block(b"12345678"), b"12345678")


if __name__ == "__main__":
    unittest.main()
