"""Unit tests for DES and Triple DES.

Covers the classic published single-DES values, cross-checks the two
alternative IP/FP and f implementations against the spec tables and against
each other, and exercises the 3DES vector plus round trips.
"""

import random
import unittest

from src.DES import DES, TripleDES, IP, FP, SPBOXES, _build_spboxes, \
    ip_perm_alt, fp_perm_alt
from tests.vectors import DES3_KATS, DES_KATS


def reference_permutation(value, perm, width):
    """Reference permutation by 1-based table index, for cross-checking.

    Deliberately written straight from the definition rather than reusing the
    implementation's helper, so it is an independent check.
    """
    out = 0
    for p in perm:
        src = width - 1 - (p - 1)
        out = (out << 1) | ((value >> src) & 1)
    return out


class PermutationTestCase(unittest.TestCase):
    """The alternative IP/FP networks agree with the spec tables."""

    SAMPLES = 500

    def setUp(self):
        """Seed a reproducible generator so failures are debuggable."""
        self.rng = random.Random(42)

    def random_word(self):
        """Return one random 64-bit word."""
        return self.rng.getrandbits(64)

    def test_ip_alt_matches_table(self):
        """ip_perm_alt equals a reference implementation of IP."""
        for _ in range(self.SAMPLES):
            x = self.random_word()
            with self.subTest(value=x):
                self.assertEqual(ip_perm_alt(x), reference_permutation(x, IP, 64))

    def test_fp_alt_matches_table(self):
        """fp_perm_alt equals a reference implementation of FP."""
        for _ in range(self.SAMPLES):
            x = self.random_word()
            with self.subTest(value=x):
                self.assertEqual(fp_perm_alt(x), reference_permutation(x, FP, 64))

    def test_fp_alt_inverts_ip_alt(self):
        """fp_perm_alt(ip_perm_alt(x)) is the identity."""
        for _ in range(self.SAMPLES):
            x = self.random_word()
            with self.subTest(value=x):
                self.assertEqual(fp_perm_alt(ip_perm_alt(x)), x)


class SPBoxTestCase(unittest.TestCase):
    """The hard-coded S-box table matches its derivation from the spec."""

    def test_literal_matches_generator(self):
        """SPBOXES equals _build_spboxes()."""
        self.assertEqual(SPBOXES, _build_spboxes())


class DSKATTestCase(unittest.TestCase):
    """The three classic single-DES known-answer vectors."""

    def test_encrypt_both_implementations(self):
        """Encrypt every KAT with the table and the alternative network."""
        for use_alt in (True, False):
            for i, (key, pt, ct) in enumerate(DES_KATS):
                with self.subTest(use_alt=use_alt, vector=i + 1):
                    cipher = DES(use_alt=use_alt)
                    cipher.generate_keys(bytes.fromhex(key))
                    self.assertEqual(
                        cipher.encrypt_block(bytes.fromhex(pt)),
                        bytes.fromhex(ct))

    def test_decrypt_both_implementations(self):
        """Decrypt every KAT with the table and the alternative network."""
        for use_alt in (True, False):
            for i, (key, pt, ct) in enumerate(DES_KATS):
                with self.subTest(use_alt=use_alt, vector=i + 1):
                    cipher = DES(use_alt=use_alt)
                    cipher.generate_keys(bytes.fromhex(key))
                    self.assertEqual(
                        cipher.decrypt_block(bytes.fromhex(ct)),
                        bytes.fromhex(pt))


class DESImplementationAgreementTestCase(unittest.TestCase):
    """The fast and the naive implementations compute the same thing."""

    SAMPLES = 500

    def test_f_alt_matches_f(self):
        """f_alt equals f on random (32-bit half, 48-bit subkey) inputs."""
        rng = random.Random(123)
        cipher = DES()
        for _ in range(self.SAMPLES):
            half = rng.getrandbits(32)
            subkey = rng.getrandbits(48)
            with self.subTest(half=half, subkey=subkey):
                self.assertEqual(cipher.f(half, subkey),
                                 cipher.f_alt(half, subkey))

    def test_block_output_matches(self):
        """Both implementations agree on every KAT, encrypt and decrypt."""
        for key, pt, _ in DES_KATS:
            with self.subTest(key=key):
                fast = DES(use_alt=True)
                naive = DES(use_alt=False)
                fast.generate_keys(bytes.fromhex(key))
                naive.generate_keys(bytes.fromhex(key))
                self.assertEqual(fast.encrypt_block(bytes.fromhex(pt)),
                                 naive.encrypt_block(bytes.fromhex(pt)))
                self.assertEqual(fast.decrypt_block(bytes.fromhex(pt)),
                                 naive.decrypt_block(bytes.fromhex(pt)))


class TripleDESKATTestCase(unittest.TestCase):
    """The repository's single 3DES vector."""

    def test_encrypt(self):
        """Encrypt the 3DES vector."""
        for name, key, pt, ct in DES3_KATS:
            with self.subTest(vector=name):
                cipher = TripleDES()
                cipher.generate_keys(bytes.fromhex(key))
                self.assertEqual(cipher.encrypt_block(bytes.fromhex(pt)),
                                 bytes.fromhex(ct))

    def test_decrypt(self):
        """Decrypt the 3DES vector."""
        for name, key, pt, ct in DES3_KATS:
            with self.subTest(vector=name):
                cipher = TripleDES()
                cipher.generate_keys(bytes.fromhex(key))
                self.assertEqual(cipher.decrypt_block(bytes.fromhex(ct)),
                                 bytes.fromhex(pt))


class DESRoundTripTestCase(unittest.TestCase):
    """Multi-block round trips for DES and Triple DES."""

    DES_KEY = "AABB09182736CCDD"
    DES3_KEY = "AABB09182736CCDD123456ABCD132536c0b7a8d05f3a829c"

    def test_des_ecb_round_trip(self):
        """Two blocks round trip through ECB."""
        cipher = DES()
        cipher.generate_keys(bytes.fromhex(self.DES_KEY))
        pt = bytes(0x10 + i for i in range(16))
        ct = cipher.encrypt(pt, mode="ECB")
        self.assertNotEqual(ct, pt)
        self.assertEqual(cipher.decrypt(ct, mode="ECB"), pt)

    def test_des_cbc_round_trip(self):
        """Two blocks round trip through CBC with an explicit IV."""
        cipher = DES()
        cipher.generate_keys(bytes.fromhex(self.DES_KEY))
        pt = bytes(0xA0 + i for i in range(16))
        ct = cipher.encrypt(pt, mode="CBC", iv=bytes(8))
        self.assertNotEqual(ct, pt)
        self.assertEqual(cipher.decrypt(ct, mode="CBC", iv=bytes(8)), pt)

    def test_triple_des_round_trip(self):
        """Two blocks round trip through ECB and CBC under 3DES."""
        for mode in ("ECB", "CBC"):
            with self.subTest(mode=mode):
                cipher = TripleDES()
                cipher.generate_keys(bytes.fromhex(self.DES3_KEY))
                pt = bytes(0x30 + i for i in range(16))
                iv = (bytes.fromhex("1122334455667788") if mode == "CBC"
                      else b"")
                ct = cipher.encrypt(pt, mode=mode, iv=iv)
                self.assertNotEqual(ct, pt)
                self.assertEqual(cipher.decrypt(ct, mode=mode, iv=iv), pt)

    def test_pkcs7_padding(self):
        """A seven-byte message is padded up to one DES block and recovered."""
        cipher = DES()
        cipher.generate_keys(bytes.fromhex(self.DES_KEY))
        pt = bytes.fromhex("123456abcdcd13")
        ct = cipher.encrypt(pt, mode="ECB", padding="PKCS")
        self.assertEqual(len(ct), 8)
        self.assertEqual(cipher.decrypt(ct, mode="ECB", padding="PKCS"), pt)


if __name__ == "__main__":
    unittest.main()
