"""Unit tests for Serpent against the official NESSIE/verified vectors."""
import unittest

from src.Serpent import Serpent
from tests import cipher_test_base as base
from tests.vectors import SERPENT_KATS

# Two-block ECB and one CBC vector per key size, all produced by GNU nettle.
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


class SerpentKATTestCase(base.BlockKATTestMixin):
    """NESSIE/verified single-block vectors."""
    CipherClass = Serpent
    BLOCK_KATS = SERPENT_KATS


if __name__ == "__main__":
    unittest.main()
