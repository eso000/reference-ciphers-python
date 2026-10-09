"""Unit tests for Blowfish against Schneier's official published vectors."""

import unittest

from refciphers.Blowfish import Blowfish
from tests import cipher_test_base as base
from tests.vectors import BLOWFISH_OFFICIAL, BLOWFISH_SET_KEY, BLOWFISH_SET_KEY_PT


def _build_blowfish_kats():
    """Collect the official ECB and set_key vectors as (name, key, pt, ct).

    Built inside a function so the loop variables stay local instead of
    leaking into module scope, where the round-trip tests reuse those names.
    """
    kats = []
    for i, (key, pt, ct) in enumerate(BLOWFISH_OFFICIAL):
        kats.append((f"official ecb {i + 1:02d}", key, pt, ct))
    for key, ct in BLOWFISH_SET_KEY:
        kats.append((f"set_key {len(key) * 4}", key, BLOWFISH_SET_KEY_PT, ct))
    return kats


_BLOWFISH_KATS = _build_blowfish_kats()


class BlowfishKATTestCase(base.BlockKATTestMixin):
    """The official ECB set and the official set_key vectors."""

    CipherClass = Blowfish
    BLOCK_KATS = _BLOWFISH_KATS


class BlowfishRoundTripTestCase(base.CBCRoundTripTestMixin):
    """Multi-block round trips through ECB and CBC."""

    CipherClass = Blowfish
    KEYS = (("blowfish", "0123456789abcdef"),)
    ECB_PT_LEN = 24
    CBC_KEY = "0123456789abcdef"
    CBC_IV = "1122334455667788"
    CBC_PT_SEED = 0x30
    CBC_PT_LEN = 16


class BlowfishPaddingTestCase(unittest.TestCase):
    """PKCS#7 padding on 8-byte blocks."""

    KEY = "AABB09182736CCDD"

    def test_pkcs7_padding(self):
        """A partial block is padded up to one full block and recovered."""
        cipher = Blowfish()
        cipher.generate_keys(bytes.fromhex(self.KEY))
        pt = b"Blowfis"
        ct = cipher.encrypt(pt, mode="ECB", padding="PKCS")
        self.assertEqual(len(ct), 8)
        self.assertEqual(cipher.decrypt(ct, mode="ECB", padding="PKCS"), pt)


if __name__ == "__main__":
    unittest.main()
