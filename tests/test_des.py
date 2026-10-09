"""Unit tests for DES and Triple DES.

Covers the classic published single-DES values, cross-checks the
alternative IP/FP and f implementations against the spec tables and against
each other, verifies that both use_alt settings compute the same cipher
(DES and Triple DES), and exercises the 3DES vector plus round trips.
"""

import random
import unittest

from refciphers.DES import (
    DES,
    TripleDES,
    IP,
    FP,
    SPBOXES,
    _build_spboxes,
    ip_perm_alt,
    fp_perm_alt,
)
from tests import cipher_test_base as base
from tests.vectors import DES_KATS


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

    def test_encrypt_kats(self):
        """Encrypt every vector with the default implementation."""
        for i, (key, pt, ct) in enumerate(DES_KATS):
            with self.subTest(vector=i + 1):
                cipher = DES()
                cipher.generate_keys(bytes.fromhex(key))
                self.assertEqual(
                    cipher.encrypt_block(bytes.fromhex(pt)), bytes.fromhex(ct)
                )

    def test_decrypt_kats(self):
        """Decrypt every vector with the default implementation."""
        for i, (key, pt, ct) in enumerate(DES_KATS):
            with self.subTest(vector=i + 1):
                cipher = DES()
                cipher.generate_keys(bytes.fromhex(key))
                self.assertEqual(
                    cipher.decrypt_block(bytes.fromhex(ct)), bytes.fromhex(pt)
                )


class DESImplementationAgreementTestCase(unittest.TestCase):
    """The alternative round function matches the table-driven one."""

    SAMPLES = 500

    def test_f_alt_matches_f(self):
        """f_alt equals f on random (32-bit half, 48-bit subkey) inputs."""
        rng = random.Random(123)
        cipher = DES()
        for _ in range(self.SAMPLES):
            half = rng.getrandbits(32)
            subkey = rng.getrandbits(48)
            with self.subTest(half=half, subkey=subkey):
                self.assertEqual(cipher.f(half, subkey), cipher.f_alt(half, subkey))


class DESAltTestCase(base.AltAgreementTestMixin):
    """Both DES implementations compute the same cipher."""

    CipherClass = DES
    KEY_SIZES = (8,)


class TripleDESAltTestCase(base.AltAgreementTestMixin):
    """Both Triple DES implementations compute the same cipher."""

    CipherClass = TripleDES
    KEY_SIZES = (24,)


class TripleDESEDETestCase(unittest.TestCase):
    """3DES EDE consistency, without a published KAT.

    No triple-DES vector in this module has confirmed provenance, so 3DES is
    checked structurally rather than against an expected ciphertext. These are
    the properties that catch key-order, key-assignment and direction
    mistakes, which a plain encrypt/decrypt round trip cannot.
    """

    KEY = "AABB09182736CCDD123456ABCD132536c0b7a8d05f3a829c"
    K1, K2, K3 = (KEY[:16], KEY[16:32], KEY[32:])
    BLOCK = bytes.fromhex("0123456789ABCDEF")

    def keyed(self, keys):
        """Return a TripleDES loaded with the concatenated hex ``keys``."""
        cipher = TripleDES()
        cipher.generate_keys(bytes.fromhex("".join(keys)))
        return cipher

    def test_key_split_matches_layer_order(self):
        """Each 24-byte key third lands on the layer that uses it.

        Catches generate_keys assigning the key thirds to the DES instances
        in the wrong order.
        """
        cipher = self.keyed((self.K1, self.K2, self.K3))
        single = DES()
        for layer, key_hex in (
            (cipher.des1, self.K1),
            (cipher.des2, self.K2),
            (cipher.des3, self.K3),
        ):
            single.generate_keys(bytes.fromhex(key_hex))
            self.assertEqual(layer.subkeys, single.subkeys)

    def test_three_equal_keys_reduce_to_single_des(self):
        """When all three keys match, EDE collapses to one plain DES pass.

        E_K(D_K(E_K(x))) == E_K(x), so this is a real algebraic property of
        the construction, not a restatement of the code.
        """
        cipher = self.keyed((self.K1, self.K1, self.K1))
        single = DES()
        single.generate_keys(bytes.fromhex(self.K1))
        self.assertEqual(
            cipher.encrypt_block(self.BLOCK), single.encrypt_block(self.BLOCK)
        )
        self.assertEqual(
            cipher.decrypt_block(self.BLOCK), single.decrypt_block(self.BLOCK)
        )

    def test_layers_are_encrypt_decrypt_encrypt(self):
        """The outer layers encrypt and the middle layer decrypts."""
        cipher = self.keyed((self.K1, self.K2, self.K3))
        single = DES()
        single.generate_keys(bytes.fromhex(self.K1))
        step1 = single.encrypt_block(self.BLOCK)

        single.generate_keys(bytes.fromhex(self.K2))
        step2 = single.decrypt_block(step1)

        single.generate_keys(bytes.fromhex(self.K3))
        self.assertEqual(cipher.encrypt_block(self.BLOCK), single.encrypt_block(step2))

    def test_decrypt_is_the_inverse(self):
        """EDE decryption undoes EDE encryption on random blocks."""
        rng = random.Random(7)
        cipher = self.keyed((self.K1, self.K2, self.K3))
        for _ in range(64):
            block = rng.randbytes(8)
            with self.subTest(block=block):
                self.assertEqual(
                    cipher.decrypt_block(cipher.encrypt_block(block)), block
                )


class DESRoundTripTestCase(base.CBCRoundTripTestMixin):
    """Multi-block round trips through ECB and CBC under single DES."""

    CipherClass = DES
    KEYS = (("DES", "AABB09182736CCDD"),)
    ECB_PT_LEN = 16
    ECB_PT_SEED = 0x10
    CBC_KEY = "AABB09182736CCDD"
    CBC_IV = "0000000000000000"
    CBC_PT_SEED = 0xA0
    CBC_PT_LEN = 16


class TripleDESRoundTripTestCase(base.CBCRoundTripTestMixin):
    """Multi-block round trips through ECB and CBC under Triple DES."""

    CipherClass = TripleDES
    KEYS = (("3DES", "AABB09182736CCDD123456ABCD132536c0b7a8d05f3a829c"),)
    ECB_PT_LEN = 16
    ECB_PT_SEED = 0x30
    CBC_KEY = "AABB09182736CCDD123456ABCD132536c0b7a8d05f3a829c"
    CBC_IV = "1122334455667788"
    CBC_PT_SEED = 0x30
    CBC_PT_LEN = 16


class DESPaddingTestCase(unittest.TestCase):
    """PKCS#7 padding on 8-byte blocks."""

    KEY = "AABB09182736CCDD"

    def test_pkcs7_padding(self):
        """A seven-byte message is padded up to one DES block and recovered."""
        cipher = DES()
        cipher.generate_keys(bytes.fromhex(self.KEY))
        pt = bytes.fromhex("123456abcdcd13")
        ct = cipher.encrypt(pt, mode="ECB", padding="PKCS")
        self.assertEqual(len(ct), 8)
        self.assertEqual(cipher.decrypt(ct, mode="ECB", padding="PKCS"), pt)


if __name__ == "__main__":
    unittest.main()
