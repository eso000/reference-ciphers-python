"""Twofish known-answer, block-mode, and padding tests.

Vectors: official Twofish KATs (Schneier et al., B.2) for 128/192/256-bit
keys; the 128 chain continues the all-zero ciphertext as the next plaintext.
"""

from Twofish import Twofish

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


KATS = [
    ("00000000000000000000000000000000",
     "00000000000000000000000000000000", "9f589f5cf6122c32b6bfec2f2ae8c35a"),
    ("00000000000000000000000000000000",
     "9f589f5cf6122c32b6bfec2f2ae8c35a", "d491db16e7b1c39e86cb086b789f5419"),
    ("9f589f5cf6122c32b6bfec2f2ae8c35a",
     "d491db16e7b1c39e86cb086b789f5419", "019f9809de1711858faac3a3ba20fbc3"),
    ("88B2B2706B105E36B446BB6D731A1E88EFA71F788965BD44",
     "39DA69D6BA4997D585B6DC073CA341B2", "182b02d81497ea45f9daacdc29193a65"),
    ("D43BB7556EA32E46F2A282B7D45B4E0D57FF739D4DC92C1BD7FC01700CC8216F",
     "90AFE91BB288544F2C32DC239B2635E6", "6cb4561c40bf0a9705931cb6d408e7fa"),
]

KEYS = [
    ("128-bit key", "000102030405060708090a0b0c0d0e0f"),
    ("192-bit key", "000102030405060708090a0b0c0d0e0f1011121314151617"),
    ("256-bit key",
     "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"),
]


def main():
    print("== Twofish known-answer tests ==")
    for i, (key, pt, ct) in enumerate(KATS):
        name = "kat %02d" % (i + 1)
        c = Twofish()
        c.generate_keys(key)
        got = c.encrypt_block(pt)
        check(name + " encrypt", got, ct)
        check(name + " decrypt", c.decrypt_block(got), pt)

    print("== ECB multi-block round trip (all key sizes) ==")
    for label, key in KEYS:
        c = Twofish()
        c.generate_keys(key)
        pt = "".join("%02x" % (0xA5 + i) for i in range(32))
        ct = c.encrypt(pt, mode="ECB")
        check("%s: ciphertext differs from plaintext" % label, ct != pt, True)
        check("%s: encrypt+decrypt restores plaintext" % label,
              c.decrypt(ct, mode="ECB"), pt)

    print("== CBC two-block round trip ==")
    c = Twofish()
    c.generate_keys("0123456789abcdef0123456789abcdef")
    pt = "".join("%02x" % i for i in range(32))
    iv = "aa" * 16
    ct = c.encrypt(pt, mode="CBC", iv=iv)
    check("cbc two-block ciphertext differs from plaintext", ct != pt, True)
    check("cbc two-block encrypt+decrypt restores plaintext",
          c.decrypt(ct, mode="CBC", iv=iv), pt)

    print("== PKCS#7 padding (16-byte blocks) ==")
    c = Twofish()
    c.generate_keys("00112233445566778899aabbccddeeff")
    pt = "123456abcdcd13"
    ct = c.encrypt(pt, mode="ECB", padding="PKCS")
    check("7-byte input padded to one block", len(ct), 32)
    check("7-byte input round trip through PKCS padding",
          c.decrypt(ct, mode="ECB", padding="PKCS"), pt)
    ct = c.encrypt("", mode="ECB", padding="PKCS")
    check("empty input padded to one full block", len(ct), 32)
    ct = c.encrypt("00112233445566778899aabbccddeeff", mode="ECB", padding="")
    check("invalid padding is not stripped",
          len(c.decrypt(ct, mode="ECB", padding="PKCS")), 32)

    print()
    print("%d test(s) failed" % _FAILS)
    return 1 if _FAILS else 0


if __name__ == "__main__":
    raise SystemExit(main())
