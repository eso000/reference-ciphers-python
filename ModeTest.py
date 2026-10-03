"""Block-mode round trips and mode-dependent padding for every cipher.

Each cipher is run through all six modes on a three-block message with a
per-mode IV.
"""

import sys

from AES import AES
from Blowfish import Blowfish
from DES import DES, TripleDES
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


def mode_iv(mode, iv):
    """ECB takes no IV; every other mode takes the given one."""
    return b"" if mode == "ECB" else iv


def run_modes(label, cipher, block_size):
    """Round-trip a three-block message through every mode for ``cipher``."""
    length = block_size * 3
    pt = bytes((1 + i * 7 + 3) & 0xFF for i in range(length))
    for idx, mode in enumerate(MODES):
        iv = mode_iv(mode, bytes((0x20 + idx + j) & 0xFF for j in range(block_size)))
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


def raises_type_error(func):
    """Return True when calling ``func`` raises TypeError."""
    try:
        func()
    except TypeError:
        return True
    return False


KEY_SIZES = (
    (AES, (16, 24, 32)),
    (DES, (8,)),
    (TripleDES, (24,)),
    (Blowfish, tuple(range(4, 57))),
    (Twofish, (16, 24, 32)),
    (Serpent, (16, 24, 32)),
)


def check_cipher_lengths(cls, valid):
    """Check that ``cls`` rejects keys, blocks and IVs of the wrong length."""
    name = cls.__name__.lower()

    def key_rejected(n):
        return raises_value_error(lambda: cls().generate_keys(bytes(n)))

    bad = [n for n in range(66) if n not in valid]
    check(f"{name} accepts exactly its valid key sizes",
          [n for n in valid if not key_rejected(n)], list(valid))
    check(f"{name} rejects every other key size (0-65 bytes)",
          [n for n in bad if key_rejected(n)], bad)

    cipher = cls()
    cipher.generate_keys(bytes(valid[0]))
    size = cipher.get_block_size()
    for label, func in (("encrypt_block", cipher.encrypt_block),
                        ("decrypt_block", cipher.decrypt_block)):
        wrong = [n for n in (0, size - 1, size + 1, 2 * size)
                 if not raises_value_error(lambda n=n, f=func: f(bytes(n)))]
        check(f"{name} {label} rejects a block that is not {size} bytes", wrong, [])

    for mode in MODES:
        for iv in (b"", bytes(size - 1), bytes(size + 1), bytes(2 * size)):
            if mode == "ECB" and not iv:
                continue
            check(
                f"{name} {mode} rejects a {len(iv)}-byte IV",
                raises_value_error(
                    lambda m=mode, v=iv: cipher.encrypt(bytes(size), mode=m, iv=v)),
                True,
            )
            check(
                f"{name} {mode} decrypt rejects a {len(iv)}-byte IV",
                raises_value_error(
                    lambda m=mode, v=iv: cipher.decrypt(bytes(size), mode=m, iv=v)),
                True,
            )
    check(
        f"{name} ECB rejects a full-size IV",
        raises_value_error(
            lambda: cipher.encrypt(bytes(size), mode="ECB", iv=bytes(size))),
        True,
    )
    check(
        f"{name} default CBC without an IV is rejected",
        raises_value_error(lambda: cipher.encrypt(b"data")),
        True,
    )


def check_lengths():
    """Keys, blocks and IVs of the wrong length are rejected, never adjusted."""
    for cls, valid in KEY_SIZES:
        check_cipher_lengths(cls, valid)


def check_key_types():
    """Keys must be bytes-like; str (hex) keys are rejected by every cipher."""
    for cls, valid in KEY_SIZES:
        name = cls.__name__.lower()
        check(
            f"{name} hex/str key is rejected",
            raises_type_error(lambda c=cls: c().generate_keys("00" * 8)),
            True,
        )
        key = bytes(range(valid[0]))
        by_bytes, by_array = cls(), cls()
        by_bytes.generate_keys(key)
        by_array.generate_keys(bytearray(key))
        block = bytes(by_bytes.get_block_size())
        check(
            f"{name} bytearray key matches bytes key",
            by_array.encrypt_block(block),
            by_bytes.encrypt_block(block),
        )


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
                miv = mode_iv(mode, iv)
                ct = cipher.encrypt(pt, mode=mode, padding=scheme, iv=miv)
                ok &= cipher.decrypt(ct, mode=mode, padding=scheme, iv=miv) == pt
                grows &= len(ct) == (len(pt) // block_size + 1) * block_size
            check(f"{label} {mode} {scheme} round trip, always pads", ok and grows, True)

    for mode in STREAM_MODES:
        ok = True
        for pt in messages:
            ct = cipher.encrypt(pt, mode=mode, iv=iv)
            ok &= len(ct) == len(pt)
            ok &= cipher.decrypt(ct, mode=mode, iv=iv) == pt
        check(f"{label} {mode} is unpadded and length preserving", ok, True)

    check(
        f"{label} hex/str input is rejected",
        raises_type_error(lambda: cipher.encrypt("00ff", mode="ECB")),
        True,
    )
    check(
        f"{label} bytearray input is accepted",
        cipher.decrypt(cipher.encrypt(bytearray(b"xyz"), mode="ECB"), mode="ECB"),
        b"xyz",
    )

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
    c.generate_keys(bytes.fromhex("AABB09182736CCDD"))
    run_modes("blowfish", c, 8)

    print("== BlockCipher modes: Twofish (16-byte block) ==")
    c = Twofish()
    c.generate_keys(bytes.fromhex("00000000000000000000000000000000"))
    run_modes("twofish", c, 16)

    print("== BlockCipher modes: AES (16-byte block) ==")
    c = AES()
    c.generate_keys(bytes.fromhex("000102030405060708090a0b0c0d0e0f"))
    run_modes("aes", c, 16)

    print("== BlockCipher modes: Serpent (16-byte block) ==")
    c = Serpent()
    c.generate_keys(bytes.fromhex("11" * 32))
    run_modes("serpent", c, 16)

    print("== BlockCipher modes: DES (8-byte block) ==")
    c = DES()
    c.generate_keys(bytes.fromhex("AABB09182736CCDD"))
    run_modes("des", c, 8)

    print("== Strict key, block and IV lengths ==")
    check_lengths()

    print("== Key types ==")
    check_key_types()

    print("== Mode-dependent padding ==")
    key = bytes.fromhex("00112233445566778899aabbccddeeff")
    for label, cipher, block_size, key_len in (
        ("blowfish", Blowfish(), 8, 16),
        ("des", DES(), 8, 8),
        ("aes", AES(), 16, 16),
        ("twofish", Twofish(), 16, 16),
        ("serpent", Serpent(), 16, 16),
    ):
        cipher.generate_keys(key[:key_len])
        run_padding(label, cipher, block_size)

    print()
    print(f"{_FAILS} test(s) failed")
    return 1 if _FAILS else 0


if __name__ == "__main__":
    sys.exit(main())
