"""Reusable base classes and helpers for cipher unit tests.

These mixins reduce duplication across KAT-style and round-trip tests while
preserving clear subTest names so failures remain debuggable.
"""
import unittest


def _normalize_block_kats(kats):
    """Normalize KAT tuples to (name, key_hex, pt_hex, ct_hex).

    Accepts either (name, key_hex, pt_hex, ct_hex) or (key_hex, pt_hex, ct_hex).
    """
    normalized = []
    for i, item in enumerate(kats):
        if len(item) == 4:
            name, key_hex, pt_hex, ct_hex = item
            normalized.append((str(name), str(key_hex), str(pt_hex), str(ct_hex)))
        elif len(item) == 3:
            key_hex, pt_hex, ct_hex = item
            normalized.append((f"kat {i + 1:02d}", str(key_hex), str(pt_hex), str(ct_hex)))
        else:
            raise ValueError(f"Unexpected KAT format: {item!r}")
    return normalized


def _pattern_bytes(seed, length):
    """Return ``length`` plaintext bytes starting at value ``seed``, +1 each."""
    return bytes(seed + i for i in range(length))


class CipherTestBase(unittest.TestCase):
    """Shared helpers for the cipher test mixins below.

    Subclasses must set:
        CipherClass: the cipher class to instantiate (e.g. AES)
    """

    CipherClass: type

    def make_cipher(self, key_hex):
        """Build a cipher instance with ``key_hex`` loaded into its schedule."""
        cipher = self.CipherClass()
        cipher.generate_keys(bytes.fromhex(key_hex))
        return cipher


class BlockKATTestMixin(CipherTestBase):
    """Mixin for single-block encrypt/decrypt known-answer tests.

    Subclasses must set:
        CipherClass: the cipher class to instantiate (e.g. AES)
        BLOCK_KATS: iterable of (name, key_hex, pt_hex, ct_hex) or
                    (key_hex, pt_hex, ct_hex)
    """

    BLOCK_KATS = ()

    def test_encrypt_block_kats(self):
        """Every single-block plaintext encrypts to its expected ciphertext."""
        for name, key_hex, pt_hex, ct_hex in _normalize_block_kats(self.BLOCK_KATS):
            with self.subTest(name=name):
                cipher = self.make_cipher(key_hex)
                got = cipher.encrypt_block(bytes.fromhex(pt_hex)).hex()
                self.assertEqual(got, ct_hex.lower())

    def test_decrypt_block_kats(self):
        """Every single-block ciphertext decrypts to its expected plaintext."""
        for name, key_hex, pt_hex, ct_hex in _normalize_block_kats(self.BLOCK_KATS):
            with self.subTest(name=name):
                cipher = self.make_cipher(key_hex)
                got = cipher.decrypt_block(bytes.fromhex(ct_hex)).hex()
                self.assertEqual(got, pt_hex.lower())


class ModeKATTestMixin(CipherTestBase):
    """Mixin for SP800-style mode known-answer tests.

    Subclasses must set:
        CipherClass: the cipher class to instantiate
        MODE_KATS: dict mapping mode name -> list of (name, key_hex, ct_hex)
        PT_HEX: plaintext hex for all vectors (fixed)
        IV_HEX: IV hex used for non-ECB modes (or ignored for ECB)
    """

    MODE_KATS = {}
    PT_HEX = ""
    IV_HEX = ""

    def run_mode(self, mode, vectors):
        """Encrypt and decrypt every vector under ``mode`` in both directions."""
        pt = bytes.fromhex(self.PT_HEX)
        iv = bytes.fromhex(self.IV_HEX) if mode != "ECB" else b""
        for name, key_hex, ct_hex in vectors:
            with self.subTest(name=name, mode=mode):
                cipher = self.make_cipher(key_hex)
                got_ct = cipher.encrypt(pt, mode=mode, padding="", iv=iv).hex()
                self.assertEqual(got_ct, ct_hex.lower())
                got_pt = cipher.decrypt(bytes.fromhex(ct_hex), mode=mode,
                                        padding="", iv=iv).hex()
                self.assertEqual(got_pt, self.PT_HEX.lower())

    def test_mode_kats(self):
        """Every configured mode matches its known-answer vectors."""
        for mode, vectors in self.MODE_KATS.items():
            self.run_mode(mode, vectors)


class RoundTripTestMixin(CipherTestBase):
    """Mixin for multi-block ECB round-trip tests.

    Subclasses must set:
        CipherClass: the cipher class to instantiate
        KEYS: iterable of (name, key_hex) pairs round-tripped through ECB
        ECB_PT_LEN: byte length of the ECB plaintext (a whole number of blocks)

    Optional:
        ECB_PT_SEED: first byte of the plaintext pattern (default 0xA5)
    """

    KEYS = ()
    ECB_PT_SEED = 0xA5
    ECB_PT_LEN = 0

    def _assert_round_trip(self, cipher, plaintext, mode, **kwargs):
        """Encrypt ``plaintext``, check the output differs, then decrypt back."""
        ct = cipher.encrypt(plaintext, mode=mode, **kwargs)
        self.assertNotEqual(ct, plaintext)
        self.assertEqual(cipher.decrypt(ct, mode=mode, **kwargs), plaintext)

    def test_ecb_round_trip(self):
        """Multi-block plaintext round trips through ECB for every key."""
        plaintext = _pattern_bytes(self.ECB_PT_SEED, self.ECB_PT_LEN)
        for name, key_hex in self.KEYS:
            with self.subTest(key=name):
                self._assert_round_trip(self.make_cipher(key_hex), plaintext,
                                        mode="ECB")


class CBCRoundTripTestMixin(RoundTripTestMixin):
    """Extend :class:`RoundTripTestMixin` with a CBC round-trip test.

    Subclasses must additionally set:
        CBC_KEY: key hex for the CBC round trip
        CBC_IV: IV hex for the CBC round trip (exactly one block)

    Optional:
        CBC_PT_SEED: first byte of the CBC plaintext (default 0xA5)
        CBC_PT_LEN: byte length of the CBC plaintext (default: ECB_PT_LEN)
    """

    CBC_KEY = None
    CBC_IV = ""
    CBC_PT_SEED = 0xA5
    CBC_PT_LEN = None

    def test_cbc_round_trip(self):
        """Multi-block plaintext round trips through CBC with an explicit IV."""
        if self.CBC_KEY is None:
            self.skipTest("no CBC key configured")
        pt_len = self.ECB_PT_LEN if self.CBC_PT_LEN is None else self.CBC_PT_LEN
        plaintext = _pattern_bytes(self.CBC_PT_SEED, pt_len)
        cipher = self.make_cipher(self.CBC_KEY)
        self._assert_round_trip(cipher, plaintext, mode="CBC",
                                iv=bytes.fromhex(self.CBC_IV))
