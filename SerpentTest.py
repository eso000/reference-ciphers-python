"""Serpent known-answer, block-mode, and padding tests.

Vectors: the official NESSIE/verified Serpent test vectors (sets 1-4,
128/192/256-bit keys) as published by Biham et al.; values are in the
standard little-endian octet order (matching GNU nettle).
"""

import random

from Serpent import Serpent

_FAILS = 0


def check(name, got, want):
    """Print PASS/FAIL for a comparison and bump the failure counter."""
    global _FAILS  # pylint: disable=global-statement
    if isinstance(got, str) and isinstance(want, str):
        ok = got.lower() == want.lower()
    else:
        ok = got == want
    print(("PASS: " if ok else "FAIL: ") + name)
    if not ok:
        _FAILS += 1


def raises_value_error(func):
    """Return True when calling ``func`` raises ValueError."""
    try:
        func()
    except ValueError:
        return True
    return False


K256 = "1111111111111111111111111111111111111111111111111111111111111111"
P0 = "00112233445566778899aabbccddeeff"
P1 = "ea024714ad5c4d84ea024714ad5c4d84"

KATS = [
    ("128-bit set1 v0",
     "80000000000000000000000000000000",
     "00000000000000000000000000000000", "264e5481eff42a4606abda06c0bfda3d"),
    ("128-bit set2 v0",
     "00000000000000000000000000000000",
     "80000000000000000000000000000000", "a3b35de7c358ddd82644678c64b8bcbb"),
    ("128-bit set3 v0",
     "00000000000000000000000000000000",
     "00000000000000000000000000000000", "3620b17ae6a993d09618b8768266bae9"),
    ("128-bit set4 v0",
     "000102030405060708090a0b0c0d0e0f", P0,
     "563e2cf8740a27c164804560391e9b27"),
    ("128-bit set4 v1",
     "2bd6459f82c5b300952c49104881ff48", P1,
     "92d7f8ef2c36c53409f275902f06539f"),
    ("192-bit set1 v0",
     "800000000000000000000000000000000000000000000000",
     "00000000000000000000000000000000", "9e274ead9b737bb21efcfca548602689"),
    ("192-bit set2 v0",
     "000000000000000000000000000000000000000000000000",
     "80000000000000000000000000000000", "23f5f432ad687e0d4574c16459618abb"),
    ("192-bit set3 v0",
     "000000000000000000000000000000000000000000000000",
     "00000000000000000000000000000000", "a583ef976a292b406bbd5dc8256b0442"),
    ("192-bit set4 v0",
     "000102030405060708090a0b0c0d0e0f1011121314151617", P0,
     "6ab816c82de53b93005008afa2246a02"),
    ("192-bit set4 v1",
     "2bd6459f82c5b300952c49104881ff482bd6459f82c5b300", P1,
     "827b18c2678a239dfc5512842000e204"),
    ("256-bit set1 v0",
     "8000000000000000000000000000000000000000000000000000000000000000",
     "00000000000000000000000000000000", "a223aa1288463c0e2be38ebd825616c0"),
    ("256-bit set2 v0",
     "0000000000000000000000000000000000000000000000000000000000000000",
     "80000000000000000000000000000000", "8314675e8ad5c3ecd83d852bcf7f566e"),
    ("256-bit set3 v0",
     "0000000000000000000000000000000000000000000000000000000000000000",
     "00000000000000000000000000000000", "49672ba898d98df95019180445491089"),
    ("256-bit set3 v17", K256,
     "11111111111111111111111111111111", "a482eaa5d5771f2fdb2ea1a5f141b9e2"),
    ("256-bit set4 v0",
     "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
     P0, "2868b7a2d28ecd5e4fdefac3c4330074"),
    ("256-bit set4 v1",
     "2bd6459f82c5b300952c49104881ff482bd6459f82c5b300952c49104881ff48",
     P1, "3e507730776b93fdea661235e1dd99f0"),
]


def main():
    """Run Serpent S-box, KAT, key, mode, and padding checks."""
    print("== S-box gate networks vs bit-sliced table ==")
    random.seed(1)
    c = Serpent()
    total = 0
    checked_f = 0
    checked_i = 0
    for _ in range(200):
        x = [random.getrandbits(32) for _ in range(4)]
        for n in range(8):
            total += 1
            if c.apply_sbox(list(x), n, d=0) == c.apply_sbox_bit(list(x), n, d=0):
                checked_f += 1
            if c.apply_sbox(list(x), n, d=1) == c.apply_sbox_bit(list(x), n, d=1):
                checked_i += 1
    check(f"gate == table forward ({total} random words x 8 boxes)",
          checked_f, total)
    check(f"gate == table inverse ({total} random words x 8 boxes)",
          checked_i, total)

    print("== bit-sliced table: forward then inverse is identity ==")
    checked = 0
    for _ in range(200):
        x0 = [random.getrandbits(32) for _ in range(4)]
        for n in range(8):
            if c.apply_sbox_bit(c.apply_sbox_bit(list(x0), n, d=0), n, d=1) == x0:
                checked += 1
    check("table inverse == inverse of forward (all 8 boxes)", checked, total)

    print("== Serpent known-answer tests (both S-box implementations) ==")
    for alt in (True, False):
        for name, key, pt, ct in KATS:
            c = Serpent(use_alt=alt)
            c.generate_keys(bytes.fromhex(key))
            got = c.encrypt_block(bytes.fromhex(pt))
            check(f"serpent alt={alt} {name} encrypt", got.hex(), ct)
            check(f"serpent alt={alt} {name} decrypt",
                  c.decrypt_block(got).hex(), pt)

    print("== serpent alt vs table mode agree ==")
    for name, key, pt, _ in KATS:
        a = Serpent(use_alt=True)
        b = Serpent(use_alt=False)
        a.generate_keys(bytes.fromhex(key))
        b.generate_keys(bytes.fromhex(key))
        check(f"serpent alt==table encrypt ({name})",
              a.encrypt_block(bytes.fromhex(pt)),
              b.encrypt_block(bytes.fromhex(pt)))
        check(f"serpent alt==table decrypt ({name})",
              a.decrypt_block(bytes.fromhex(pt)),
              b.decrypt_block(bytes.fromhex(pt)))

    print("== serpent alt vs table multi-block ECB/CBC agree ==")
    for mode in ("ECB", "CBC"):
        a = Serpent(use_alt=True)
        b = Serpent(use_alt=False)
        a.generate_keys(bytes.fromhex(K256))
        b.generate_keys(bytes.fromhex(K256))
        pt = bytes(0x10 + i for i in range(32))
        iv = bytes(16) if mode == "CBC" else b""
        ct_a = a.encrypt(pt, mode=mode, iv=iv)
        ct_b = b.encrypt(pt, mode=mode, iv=iv)
        check(f"serpent alt==table {mode.lower()} encrypt", ct_a, ct_b)
        check(f"serpent alt==table {mode.lower()} decrypt",
              a.decrypt(ct_a, mode=mode, iv=iv), b.decrypt(ct_a, mode=mode, iv=iv))

    print("== short keys get the spec 0x01 pad ==")
    for alt in (True, False):
        for size in (16, 24):
            key = bytes(range(1, size + 1))
            short = Serpent(use_alt=alt)
            padded = Serpent(use_alt=alt)
            short.generate_keys(key)
            padded.generate_keys(key + b"\x01" + bytes(31 - size))
            check(f"serpent {size * 8}-bit key == explicit 0x01-padded 256-bit key (alt={alt})",
                  short.subkeys, padded.subkeys)

    print("== randomized round trip and alt agreement ==")
    random.seed(42)
    rt_total = 0
    rt_ok = 0
    alt_total = 0
    alt_ok = 0
    for _ in range(20):
        key = "".join(f"{random.randrange(256):02x}" for _ in range(random.choice([16, 24, 32])))
        pt = bytes(random.randrange(256) for _ in range(16))
        for alt in (True, False):
            c = Serpent(use_alt=alt)
            c.generate_keys(bytes.fromhex(key))
            ct = c.encrypt_block(pt)
            rt_total += 1
            if c.decrypt_block(ct) == pt:
                rt_ok += 1
        a = Serpent(use_alt=True)
        b = Serpent(use_alt=False)
        a.generate_keys(bytes.fromhex(key))
        b.generate_keys(bytes.fromhex(key))
        alt_total += 1
        if a.encrypt_block(pt) == b.encrypt_block(pt):
            alt_ok += 1
    check(f"random round trip decrypt(encrypt(pt)) == pt ({rt_total} cases)",
          rt_ok, rt_total)
    check(f"random alt == table ciphertext ({alt_total} cases)", alt_ok, alt_total)

    print("== ECB multi-block round trip ==")
    c = Serpent()
    c.generate_keys(bytes.fromhex(K256))
    pt = bytes(0x10 + i for i in range(32))
    ct = c.encrypt(pt, mode="ECB")
    check("ecb ciphertext differs from plaintext", ct != pt, True)
    check("ecb encrypt+decrypt restores plaintext", c.decrypt(ct, mode="ECB"), pt)

    print("== CBC multi-block round trip ==")
    c = Serpent()
    c.generate_keys(bytes.fromhex("80" + "00" * 31))
    pt = bytes(0xA0 + i for i in range(32))
    iv = bytes(16)
    ct = c.encrypt(pt, mode="CBC", iv=iv)
    check("cbc ciphertext differs from plaintext", ct != pt, True)
    check("cbc encrypt+decrypt restores plaintext",
          c.decrypt(ct, mode="CBC", iv=iv), pt)

    print("== PKCS#7 padding ==")
    c = Serpent()
    c.generate_keys(bytes.fromhex(K256))
    pt = bytes.fromhex("00112233445566778899aabbcc")
    ct = c.encrypt(pt, mode="ECB", padding="PKCS")
    check("13-byte input padded to one block", len(ct), 16)
    check("13-byte input round trip through PKCS padding",
          c.decrypt(ct, mode="ECB", padding="PKCS"), pt)
    check("2 bytes padded to one block",
          len(c.encrypt(b"\xab\xcd", mode="ECB", padding="PKCS")), 16)
    ct = c.encrypt(b"", mode="ECB", padding="PKCS")
    check("empty input padded to one full block", len(ct), 16)
    ct = c.encrypt(bytes(range(16)), mode="ECB", padding="")
    check("invalid padding is rejected",
          raises_value_error(lambda: c.decrypt(ct, mode="ECB", padding="PKCS")), True)

    print()
    print(f"{_FAILS} test(s) failed")
    return 1 if _FAILS else 0


if __name__ == "__main__":
    raise SystemExit(main())
