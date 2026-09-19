"""DES and Triple-DES known-answer, block-mode, and padding tests.

Vectors: the standard DES test values plus the repository's own single and
triple DES KATs.
"""

from DES import DES, TrippleDES

_FAILS = 0


def check(name, got, want):
    global _FAILS
    if isinstance(got, str) and isinstance(want, str):
        ok = got.lower() == want.lower()
    else:
        ok = got == want
    print(("PASS: " if ok else "FAIL: ") + name)
    if not ok:
        _FAILS += 1


DES_KATS = [
    ("133457799BBCDFF1", "0123456789ABCDEF", "85E813540F0AB405"),
    ("0E329232EA6D0D73", "8787878787878787", "0000000000000000"),
    ("AABB09182736CCDD", "123456ABCD132536", "C0B7A8D05F3A829C"),
]

DES_KEY = "AABB09182736CCDD"
DES3_KEY = "AABB09182736CCDD123456ABCD132536c0b7a8d05f3a829c"


def main():
    print("== DES known-answer tests ==")
    for i, (key, pt, ct) in enumerate(DES_KATS):
        c = DES()
        c.generate_keys(key)
        got = c.encrypt_block(pt)
        check("des kat %02d encrypt" % (i + 1), got, ct)
        check("des kat %02d decrypt" % (i + 1), c.decrypt_block(got), pt)

    print("== Triple DES known-answer test ==")
    c = TrippleDES()
    c.generate_keys(DES3_KEY)
    ct = c.encrypt_block("123456ABCD132536")
    check("3des encrypt", ct, "e6803bea92016d52")
    check("3des decrypt", c.decrypt_block(ct), "123456ABCD132536")

    print("== DES ECB multi-block round trip ==")
    c = DES()
    c.generate_keys(DES_KEY)
    pt = "".join("%02x" % (0x10 + i) for i in range(16))
    ct = c.encrypt(pt, mode="ECB")
    check("des ecb ciphertext differs from plaintext", ct != pt, True)
    check("des ecb encrypt+decrypt restores plaintext",
          c.decrypt(ct, mode="ECB"), pt)

    print("== DES CBC round trip ==")
    c = DES()
    c.generate_keys(DES_KEY)
    pt = "".join("%02x" % (0xA0 + i) for i in range(16))
    iv = "0000000000000000"
    ct = c.encrypt(pt, mode="CBC", iv=iv)
    check("des cbc ciphertext differs from plaintext", ct != pt, True)
    check("des cbc encrypt+decrypt restores plaintext",
          c.decrypt(ct, mode="CBC", iv=iv), pt)

    print("== Triple DES ECB/CBC round trip ==")
    for mode in ("ECB", "CBC"):
        c = TrippleDES()
        c.generate_keys(DES3_KEY)
        pt = "".join("%02x" % (0x30 + i) for i in range(16))
        iv = "1122334455667788" if mode == "CBC" else ""
        ct = c.encrypt(pt, mode=mode, iv=iv)
        check("3des %s ciphertext differs from plaintext" % mode.lower(),
              ct != pt, True)
        check("3des %s encrypt+decrypt restores plaintext" % mode.lower(),
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
    check("invalid padding is not stripped",
          len(c.decrypt(ct, mode="ECB", padding="PKCS")), 16)

    print()
    print("%d test(s) failed" % _FAILS)
    return 1 if _FAILS else 0


if __name__ == "__main__":
    raise SystemExit(main())
