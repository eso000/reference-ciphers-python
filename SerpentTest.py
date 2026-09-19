"""Serpent known-answer, block-mode, and padding tests.

Vectors: the official NESSIE/verified Serpent test vectors (sets 1-4,
128/192/256-bit keys) as published by Biham et al.; values are in the
standard little-endian octet order (matching GNU nettle).
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
