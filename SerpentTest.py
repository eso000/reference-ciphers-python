"""Serpent known-answer, block-mode, and padding tests.

Vectors: NESSIE set 1 plus 128- and 192-bit key values.
"""

from Serpent import Serpent

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


K256 = "1111111111111111111111111111111111111111111111111111111111111111"
P0 = "00112233445566778899aabbccddeeff"

KATS = [
    ("nessie 1",
     "8000000000000000000000000000000000000000000000000000000000000000",
     "00000000000000000000000000000000", "a223aa1288463c0e2be38ebd825616c0"),
    ("nessie 2", K256,
     "11111111111111111111111111111111", "a482eaa5d5771f2fdb2ea1a5f141b9e2"),
    ("128-bit key", "0102030405060708090a0b0c0d0e0f10", P0,
     "98874e1fbed147b9f34420e4118c4465"),
    ("192-bit key", "0102030405060708090a0b0c0d0e0f101112131415161718", P0,
     "17141e4724812f8bbe3e0ab978d1521f"),
]


def main():
    print("== Serpent known-answer tests ==")
    for name, key, pt, ct in KATS:
        c = Serpent()
        c.generate_keys(key)
        got = c.encrypt_block(bytes.fromhex(pt))
        check(name + " encrypt", got.hex(), ct)
        check(name + " decrypt", c.decrypt_block(got).hex(), pt)

    print("== ECB multi-block round trip ==")
    c = Serpent()
    c.generate_keys(K256)
    pt = "".join("%02x" % (0x10 + i) for i in range(32))
    ct = c.encrypt(pt, mode="ECB")
    check("ecb ciphertext differs from plaintext", ct != pt, True)
    check("ecb encrypt+decrypt restores plaintext", c.decrypt(ct, mode="ECB"), pt)

    print("== CBC multi-block round trip ==")
    c = Serpent()
    c.generate_keys("8000000000000000000000000000000000000000000000000000000000000000")
    pt = "".join("%02x" % (0xA0 + i) for i in range(32))
    iv = "00000000000000000000000000000000"
    ct = c.encrypt(pt, mode="CBC", iv=iv)
    check("cbc ciphertext differs from plaintext", ct != pt, True)
    check("cbc encrypt+decrypt restores plaintext",
          c.decrypt(ct, mode="CBC", iv=iv), pt)

    print("== PKCS#7 padding ==")
    c = Serpent()
    c.generate_keys(K256)
    pt = "00112233445566778899aabbcc"
    ct = c.encrypt(pt, mode="ECB", padding="PKCS")
    check("13-byte input padded to one block", len(ct), 32)
    check("13-byte input round trip through PKCS padding",
          c.decrypt(ct, mode="ECB", padding="PKCS"), pt)
    check("2 bytes padded to one block",
          len(c.encrypt("ABCD", mode="ECB", padding="PKCS")), 32)
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
