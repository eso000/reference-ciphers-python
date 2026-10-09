"""Unit tests for AES: FIPS-197 and NIST SP 800-38A known-answer vectors."""

import unittest

from cryptology.AES import AES
from tests import cipher_test_base as base
from tests.vectors import (
    AES_FIPS,
    AES_SP800_CBC,
    AES_SP800_ECB,
    AES_SP800_IV,
    AES_SP800_PT,
)


class AESKATTestCase(base.BlockKATTestMixin):
    """Single-block vectors from FIPS-197 appendix C."""

    CipherClass = AES
    BLOCK_KATS = AES_FIPS


class AESModeKATTestCase(base.ModeKATTestMixin):
    """Four-block mode vectors from NIST SP 800-38A."""

    CipherClass = AES
    PT_HEX = AES_SP800_PT
    IV_HEX = AES_SP800_IV
    MODE_KATS = {
        "ECB": AES_SP800_ECB,
        "CBC": AES_SP800_CBC,
    }


class AESRoundTripTestCase(base.RoundTripTestMixin):
    """Two-block round trip through ECB for every key size."""

    CipherClass = AES
    KEYS = (
        ("AES-128", "000102030405060708090a0b0c0d0e0f"),
        ("AES-192", "000102030405060708090a0b0c0d0e0f1011121314151617"),
        ("AES-256", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"),
    )
    ECB_PT_LEN = 32


if __name__ == "__main__":
    unittest.main()
