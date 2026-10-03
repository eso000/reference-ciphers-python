"""DES and Triple-DES known-answer, block-mode, and padding tests.

Vectors: the standard DES test values plus the repository's own single and
triple DES KATs.
"""

import random

from DES import (DES, TripleDES, IP, FP, SPBOXES, _build_spboxes,
                 ip_perm_alt, fp_perm_alt)

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


DES_KATS = [
    ("133457799BBCDFF1", "0123456789ABCDEF", "85E813540F0AB405"),
    ("0E329232EA6D0D73", "8787878787878787", "0000000000000000"),
    ("AABB09182736CCDD", "123456ABCD132536", "C0B7A8D05F3A829C"),
]

DES_KEY = "AABB09182736CCDD"
DES3_KEY = "AABB09182736CCDD123456ABCD132536c0b7a8d05f3a829c"


def permutate_int_reference(val, perm, width):
    """Reference permutation by table index, for cross-checking the networks."""
    out = 0
    for p in perm:
        src = width - 1 - (p - 1)
        out = (out << 1) | ((val >> src) & 1)
    return out


def main():
    """Run DES/3DES permutation, KAT, mode, and padding checks."""
    print("== IP/FP alternative networks vs spec tables ==")
    random.seed(42)
    checked = 0
    for _ in range(500):
        x = random.getrandbits(64)
        if ip_perm_alt(x) == permutate_int_reference(x, IP, 64):
            checked += 1
    check("ip_perm_alt equals IP table (500 random blocks)", checked, 500)
    checked = 0
    for _ in range(500):
        x = random.getrandbits(64)
        if fp_perm_alt(x) == permutate_int_reference(x, FP, 64):
            checked += 1
    check("fp_perm_alt equals FP table (500 random blocks)", checked, 500)
    checked = 0
    for _ in range(500):
        x = random.getrandbits(64)
        if fp_perm_alt(ip_perm_alt(x)) == x:
            checked += 1
    check("fp_perm_alt(ip_perm_alt(x)) == x (500 random blocks)", checked, 500)

    print("== SPBOXES literal vs reference generator ==")
    check("SPBOXES literal == _build_spboxes() derivation",
          SPBOXES == _build_spboxes(), True)

    print("== DES known-answer tests (both IP/FP implementations) ==")
    for alt in (True, False):
        for i, (key, pt, ct) in enumerate(DES_KATS):
            c = DES(use_alt=alt)
            c.generate_keys(key)
            got = c.encrypt_block(bytes.fromhex(pt))
            check(f"des alt={alt} kat {i + 1:02d} encrypt", got.hex(), ct)
            check(f"des alt={alt} kat {i + 1:02d} decrypt",
                  c.decrypt_block(got).hex(), pt)

    print("== f() vs SP-fused f_alt agree ==")
    c = DES()
    checked = 0
    for _ in range(500):
        blk = random.getrandbits(32)
        subkey = random.getrandbits(48)
        if c.f(blk, subkey) == c.f_alt(blk, subkey):
            checked += 1
    check("f_alt == f on random (32-bit half, 48-bit subkey)", checked, 500)

    print("== DES alt vs naive mode agree ==")
    for key, pt, _ in DES_KATS:
        a = DES(use_alt=True)
        b = DES(use_alt=False)
        a.generate_keys(key)
        b.generate_keys(key)
        check(f"des alt==naive encrypt ({key})",
              a.encrypt_block(bytes.fromhex(pt)),
              b.encrypt_block(bytes.fromhex(pt)))
        check(f"des alt==naive decrypt ({key})",
              a.decrypt_block(bytes.fromhex(pt)),
              b.decrypt_block(bytes.fromhex(pt)))

    print("== Triple DES known-answer test ==")
    c = TripleDES()
    c.generate_keys(DES3_KEY)
    ct = c.encrypt_block(bytes.fromhex("123456ABCD132536"))
    check("3des encrypt", ct.hex(), "e6803bea92016d52")
    check("3des decrypt", c.decrypt_block(ct).hex(), "123456ABCD132536")

    print("== DES ECB multi-block round trip ==")
    c = DES()
    c.generate_keys(DES_KEY)
    pt = "".join(f"{0x10 + i:02x}" for i in range(16))
    ct = c.encrypt(pt, mode="ECB")
    check("des ecb ciphertext differs from plaintext", ct != pt, True)
    check("des ecb encrypt+decrypt restores plaintext",
          c.decrypt(ct, mode="ECB"), pt)

    print("== DES CBC round trip ==")
    c = DES()
    c.generate_keys(DES_KEY)
    pt = "".join(f"{0xA0 + i:02x}" for i in range(16))
    iv = "0000000000000000"
    ct = c.encrypt(pt, mode="CBC", iv=iv)
    check("des cbc ciphertext differs from plaintext", ct != pt, True)
    check("des cbc encrypt+decrypt restores plaintext",
          c.decrypt(ct, mode="CBC", iv=iv), pt)

    print("== Triple DES ECB/CBC round trip ==")
    for mode in ("ECB", "CBC"):
        c = TripleDES()
        c.generate_keys(DES3_KEY)
        pt = "".join(f"{0x30 + i:02x}" for i in range(16))
        iv = "1122334455667788" if mode == "CBC" else ""
        ct = c.encrypt(pt, mode=mode, iv=iv)
        check(f"3des {mode.lower()} ciphertext differs from plaintext",
              ct != pt, True)
        check(f"3des {mode.lower()} encrypt+decrypt restores plaintext",
              c.decrypt(ct, mode=mode, iv=iv), pt)

    print("== PKCS#7 padding ==")
    c = DES()
    c.generate_keys(DES_KEY)
    pt = "123456abcdcd13"
    ct = c.encrypt(pt, mode="ECB", padding="PKCS")
    check("7-byte input padded to one block", len(ct), 16)
    check("7-byte input round trip through PKCS padding",
          c.decrypt(ct, mode="ECB", padding="PKCS"), pt)
    ct = c.encrypt("", mode="ECB", padding="PKCS")
    check("empty input padded to one full block", len(ct), 16)
    ct = c.encrypt("00112233445566ff", mode="ECB", padding="")
    check("invalid padding is rejected",
          raises_value_error(lambda: c.decrypt(ct, mode="ECB", padding="PKCS")), True)

    print()
    print(f"{_FAILS} test(s) failed")
    return 1 if _FAILS else 0


if __name__ == "__main__":
    raise SystemExit(main())
