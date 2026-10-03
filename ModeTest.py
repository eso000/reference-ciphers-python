"""Block-mode round trips and mode-dependent padding for every cipher.

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
PADDED_MODES = ("ECB", "CBC", "PCBC")
STREAM_MODES = ("CFB", "OFB", "CTR")
SCHEMES = ("PKCS", "ANSI X9.23", "ISO 7816-4", "bit", "TBC")


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


def raises_value_error(func):
    """Return True when calling ``func`` raises ValueError."""
    try:
        func()
    except ValueError:
        return True
    return False


def run_padding(label, cipher, block_size):
    """Check mode-dependent padding for lengths around block boundaries."""
    iv = bytes(range(block_size))
    lengths = (0, 1, block_size - 1, block_size, block_size + 1, 2 * block_size)
    lookalikes = (
        b"A" * (block_size - 1) + b"\x80",
        b"A" * (block_size - 1) + b"\x01",
        b"A" * (block_size - 1) + b"\xff",
        b"\x00" * block_size,
    )
    messages = [bytes((i * 11 + 5) & 0x7F for i in range(n)) for n in lengths]
    messages += list(lookalikes)

    for mode in PADDED_MODES:
        for scheme in SCHEMES:
            ok, grows = True, True
            for pt in messages:
                ct = cipher.encrypt(pt, mode=mode, padding=scheme, iv=iv)
                ok &= cipher.decrypt(ct, mode=mode, padding=scheme, iv=iv) == pt
                grows &= len(ct) == (len(pt) // block_size + 1) * block_size
            check(f"{label} {mode} {scheme} round trip, always pads", ok and grows, True)

    for mode in STREAM_MODES:
        ok = True
        for pt in messages:
            ct = cipher.encrypt(pt, mode=mode, iv=iv)
            ok &= len(ct) == len(pt)
            ok &= cipher.decrypt(ct, mode=mode, iv=iv) == pt
        check(f"{label} {mode} is unpadded and length preserving", ok, True)

    short = b"abc"
    check(
        f"{label} unpadded block mode rejects a partial block",
        raises_value_error(lambda: cipher.encrypt(short, mode="CBC", padding="", iv=iv)),
        True,
    )
    ct = cipher.encrypt(b"A" * block_size, mode="CBC", padding="", iv=iv)
    check(
        f"{label} malformed padding is rejected",
        raises_value_error(lambda: cipher.decrypt(ct, mode="CBC", padding="PKCS", iv=iv)),
        True,
    )
    check(
        f"{label} ciphertext that is not block-aligned is rejected",
        raises_value_error(lambda: cipher.decrypt(ct[:-1], mode="CBC", padding="PKCS", iv=iv)),
        True,
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

    print("== Mode-dependent padding ==")
    for label, cipher, block_size in (
        ("blowfish", Blowfish(), 8),
        ("des", DES(), 8),
        ("aes", AES(), 16),
        ("twofish", Twofish(), 16),
        ("serpent", Serpent(), 16),
    ):
        cipher.generate_keys("00112233445566778899aabbccddeeff")
        run_padding(label, cipher, block_size)

    print()
    print(f"{_FAILS} test(s) failed")
    return 1 if _FAILS else 0


if __name__ == "__main__":
    sys.exit(main())
