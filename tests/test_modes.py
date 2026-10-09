"""Unit tests for block modes, padding and input validation.

Every cipher is run through all six modes on a three-block message with a
per-mode IV, and every padding scheme is exercised around the block
boundaries. Keys, blocks and IVs of the wrong length are rejected outright.
"""

import unittest

from refciphers.AES import AES
from refciphers.Blowfish import Blowfish
from refciphers.DES import DES, TripleDES
from refciphers.Serpent import Serpent
from refciphers.Twofish import Twofish

MODES = ("ECB", "CBC", "PCBC", "CFB", "OFB", "CTR")
PADDED_MODES = ("ECB", "CBC", "PCBC")
STREAM_MODES = ("CFB", "OFB", "CTR")
SCHEMES = ("PKCS", "ANSI X9.23", "ISO 7816-4", "bit", "TBC")

# Cipher classes with the key sizes each one accepts, in bytes.
KEY_SIZES = (
    (AES, (16, 24, 32)),
    (DES, (8,)),
    (TripleDES, (24,)),
    (Blowfish, tuple(range(4, 57))),
    (Twofish, (16, 24, 32)),
    (Serpent, (16, 24, 32)),
)


# One keyed instance per cipher for the mode and padding sweeps.
def keyed_ciphers():
    """Return (label, cipher) pairs with a usable key already generated."""
    return [
        ("aes", _keyed(AES, "000102030405060708090a0b0c0d0e0f")),
        ("des", _keyed(DES, "AABB09182736CCDD")),
        ("blowfish", _keyed(Blowfish, "00112233445566778899aabbccddeeff")),
        ("twofish", _keyed(Twofish, "00000000000000000000000000000000")),
        ("serpent", _keyed(Serpent, "11" * 32)),
    ]


def _keyed(cls, key_hex):
    """Return a ``cls`` instance with ``key_hex`` loaded into its key schedule."""
    cipher = cls()
    cipher.generate_keys(bytes.fromhex(key_hex))
    return cipher


def mode_iv(mode, iv):
    """ECB takes no IV; every other mode takes the given one."""
    return b"" if mode == "ECB" else iv


class BlockModesTestCase(unittest.TestCase):
    """Round trips through ECB, CBC, PCBC, CFB, OFB and CTR."""

    def test_all_modes_round_trip(self):
        """A three-block message survives a round trip in every mode."""
        for label, cipher in keyed_ciphers():
            size = cipher.block_size
            pt = bytes((1 + i * 7 + 3) & 0xFF for i in range(size * 3))
            for idx, mode in enumerate(MODES):
                with self.subTest(cipher=label, mode=mode):
                    iv = mode_iv(
                        mode, bytes((0x20 + idx + j) & 0xFF for j in range(size))
                    )
                    ct = cipher.encrypt(pt, mode=mode, padding="", iv=iv)
                    self.assertNotEqual(ct, pt)
                    self.assertEqual(
                        cipher.decrypt(ct, mode=mode, padding="", iv=iv), pt
                    )


class InputValidationTestCase(unittest.TestCase):
    """Keys, blocks and IVs of the wrong length are rejected, never adjusted."""

    def test_key_sizes(self):
        """Each cipher accepts exactly its valid key sizes."""
        for cls, _valid in KEY_SIZES:
            name = cls.__name__.lower()
            for n in range(66):
                with self.subTest(cipher=name, key_size=n):
                    if n in _valid:
                        cls().generate_keys(bytes(n))
                    else:
                        with self.assertRaises(ValueError):
                            cls().generate_keys(bytes(n))

    def test_block_sizes(self):
        """encrypt_block/decrypt_block reject anything but one full block."""
        for cls, _valid in KEY_SIZES:
            cipher = _keyed(cls, "00" * _valid[0])
            size = cipher.block_size
            for func in (cipher.encrypt_block, cipher.decrypt_block):
                for n in (0, size - 1, size + 1, 2 * size):
                    with self.subTest(cipher=cls.__name__, block_size=n):
                        with self.assertRaises(ValueError):
                            func(bytes(n))

    def test_iv_sizes(self):
        """Every mode except ECB rejects an IV that is not one full block."""
        for cls, _valid in KEY_SIZES:
            cipher = _keyed(cls, "00" * _valid[0])
            size = cipher.block_size
            for mode in MODES:
                for n in (size - 1, size + 1, 2 * size):
                    iv = bytes(n)
                    with self.subTest(cipher=cls.__name__, mode=mode, iv_size=n):
                        with self.assertRaises(ValueError):
                            cipher.encrypt(bytes(size), mode=mode, iv=iv)
                        with self.assertRaises(ValueError):
                            cipher.decrypt(bytes(size), mode=mode, iv=iv)

    def test_ecb_rejects_iv(self):
        """ECB takes no IV at all."""
        for cls, _valid in KEY_SIZES:
            cipher = _keyed(cls, "00" * _valid[0])
            with self.subTest(cipher=cls.__name__):
                with self.assertRaises(ValueError):
                    cipher.encrypt(
                        bytes(cipher.block_size),
                        mode="ECB",
                        iv=bytes(cipher.block_size),
                    )

    def test_cbc_requires_iv(self):
        """The default mode is CBC and it refuses to invent an IV."""
        for cls, _valid in KEY_SIZES:
            cipher = _keyed(cls, "00" * _valid[0])
            with self.subTest(cipher=cls.__name__):
                with self.assertRaises(ValueError):
                    cipher.encrypt(b"data")

    def test_str_keys_rejected(self):
        """Keys must be bytes-like; str (hex) keys are rejected everywhere."""
        for cls, _valid in KEY_SIZES:
            with self.subTest(cipher=cls.__name__):
                with self.assertRaises(TypeError):
                    cls().generate_keys("00" * 8)

    def test_bytearray_key_matches_bytes_key(self):
        """A bytearray key schedules identically to the equivalent bytes key."""
        for cls, _valid in KEY_SIZES:
            name = cls.__name__.lower()
            key = bytes(range(_valid[0]))
            by_bytes = _keyed(cls, key.hex())
            by_array = cls()
            by_array.generate_keys(bytearray(key))
            block = bytes(by_bytes.block_size)
            with self.subTest(cipher=name):
                self.assertEqual(
                    by_array.encrypt_block(block), by_bytes.encrypt_block(block)
                )


class PaddingTestCase(unittest.TestCase):
    """Mode-dependent padding for lengths around the block boundaries."""

    def messages(self, block_size):
        """Plaintexts of every interesting length plus padding look-alikes."""
        lengths = (0, 1, block_size - 1, block_size, block_size + 1, 2 * block_size)
        lookalikes = (
            b"A" * (block_size - 1) + b"\x80",
            b"A" * (block_size - 1) + b"\x01",
            b"A" * (block_size - 1) + b"\xff",
            b"\x00" * block_size,
        )
        generated = [bytes((i * 11 + 5) & 0x7F for i in range(n)) for n in lengths]
        return generated + list(lookalikes)

    def test_block_modes_always_pad(self):
        """Block modes round trip and always add at least one padding byte."""
        for label, cipher in keyed_ciphers():
            size = cipher.block_size
            iv = bytes(range(size))
            for mode in PADDED_MODES:
                for scheme in SCHEMES:
                    for pt in self.messages(size):
                        with self.subTest(
                            cipher=label, mode=mode, padding=scheme, length=len(pt)
                        ):
                            miv = mode_iv(mode, iv)
                            ct = cipher.encrypt(pt, mode=mode, padding=scheme, iv=miv)
                            self.assertEqual(len(ct), (len(pt) // size + 1) * size)
                            self.assertEqual(
                                cipher.decrypt(ct, mode=mode, padding=scheme, iv=miv),
                                pt,
                            )

    def test_stream_modes_are_unpadded(self):
        """Keystream modes preserve the plaintext length exactly."""
        for label, cipher in keyed_ciphers():
            size = cipher.block_size
            iv = bytes(range(size))
            for mode in STREAM_MODES:
                for pt in self.messages(size):
                    with self.subTest(cipher=label, mode=mode, length=len(pt)):
                        ct = cipher.encrypt(pt, mode=mode, iv=iv)
                        self.assertEqual(len(ct), len(pt))
                        self.assertEqual(cipher.decrypt(ct, mode=mode, iv=iv), pt)

    def test_str_input_rejected_bytearray_accepted(self):
        """str is never guessed as hex; bytearray is accepted."""
        for label, cipher in keyed_ciphers():
            with self.subTest(cipher=label):
                with self.assertRaises(TypeError):
                    cipher.encrypt("00ff", mode="ECB")
                ct = cipher.encrypt(bytearray(b"xyz"), mode="ECB")
                self.assertEqual(cipher.decrypt(ct, mode="ECB"), b"xyz")

    def test_unpadded_block_mode_rejects_partial_block(self):
        """Without padding, a message must already be block-aligned."""
        for label, cipher in keyed_ciphers():
            size = cipher.block_size
            iv = bytes(range(size))
            with self.subTest(cipher=label):
                with self.assertRaises(ValueError):
                    cipher.encrypt(b"abc", mode="CBC", padding="", iv=iv)

    def test_malformed_padding_rejected(self):
        """Unpadded ciphertext is not silently accepted as padded."""
        for label, cipher in keyed_ciphers():
            size = cipher.block_size
            iv = bytes(range(size))
            ct = cipher.encrypt(b"A" * size, mode="CBC", padding="", iv=iv)
            with self.subTest(cipher=label):
                with self.assertRaises(ValueError):
                    cipher.decrypt(ct, mode="CBC", padding="PKCS", iv=iv)

    def test_misaligned_ciphertext_rejected(self):
        """Ciphertext that is not a whole number of blocks is rejected."""
        for label, cipher in keyed_ciphers():
            size = cipher.block_size
            iv = bytes(range(size))
            ct = cipher.encrypt(b"A" * size, mode="CBC", padding="", iv=iv)
            with self.subTest(cipher=label):
                with self.assertRaises(ValueError):
                    cipher.decrypt(ct[:-1], mode="CBC", padding="PKCS", iv=iv)


if __name__ == "__main__":
    unittest.main()
