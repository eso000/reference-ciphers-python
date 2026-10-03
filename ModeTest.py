"""Block-mode round trips (ECB/CBC/PCBC/CFB/OFB/CTR) for every cipher.

Each cipher is run through all six modes on a three-block message with a
per-mode IV.
"""

import sys

from AES import AES
from Blowfish import Blowfish
from DES import DES
from Serpent import Serpent
from Twofish import Twofish

_FAILS = 0

MODES = ("ECB", "CBC", "PCBC", "CFB", "OFB", "CTR")


def check(name, got, want):
    """Print PASS/FAIL for a comparison and bump the failure counter."""
    global _FAILS  # pylint: disable=global-statement
    ok = got == want
    print(("PASS: " if ok else "FAIL: ") + name)
    if not ok:
        _FAILS += 1


def run_modes(label, cipher, block_size):
    """Round-trip a three-block message through every mode for ``cipher``."""
    length = block_size * 3
    pt = bytes((1 + i * 7 + 3) & 0xFF for i in range(length))
    for idx, mode in enumerate(MODES):
        iv = bytes((0x20 + idx + j) & 0xFF for j in range(block_size))
        ct = cipher.encrypt(pt, mode=mode, padding="", iv=iv)
        check(f"{label} {mode} ciphertext differs from plaintext", ct != pt, True)
        check(
            f"{label} {mode} encrypt+decrypt restores plaintext",
            cipher.decrypt(ct, mode=mode, padding="", iv=iv),
            pt,
        )


def main():
    """Exercise all six block modes across every cipher."""
    print("== BlockCipher modes: Blowfish (8-byte block) ==")
    c = Blowfish()
    c.generate_keys("AABB09182736CCDD")
    run_modes("blowfish", c, 8)

    print("== BlockCipher modes: Twofish (16-byte block) ==")
    c = Twofish()
    c.generate_keys("00000000000000000000000000000000")
    run_modes("twofish", c, 16)

    print("== BlockCipher modes: AES (16-byte block) ==")
    c = AES()
    c.generate_keys("000102030405060708090a0b0c0d0e0f")
    run_modes("aes", c, 16)

    print("== BlockCipher modes: Serpent (16-byte block) ==")
    c = Serpent()
    c.generate_keys(
        "1111111111111111111111111111111111111111111111111111111111111111"
    )
    run_modes("serpent", c, 16)

    print("== BlockCipher modes: DES (8-byte block) ==")
    c = DES()
    c.generate_keys("AABB09182736CCDD")
    run_modes("des", c, 8)

    print()
    print(f"{_FAILS} test(s) failed")
    return 1 if _FAILS else 0


if __name__ == "__main__":
    sys.exit(main())
