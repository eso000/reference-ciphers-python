"""AES known-answer, block-mode, and padding tests.

Vectors: FIPS-197 C.1/C.2/C.3 and the full four-block NIST SP 800-38A
ECB and CBC sets (F.1.1/F.1.2/F.1.3 and F.2.1/F.2.2/F.2.3).
"""

from AES import AES

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


K128 = "000102030405060708090a0b0c0d0e0f"
K192 = "000102030405060708090a0b0c0d0e0f1011121314151617"
K256 = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"

FIPS = [
    ("AES-128", K128, "00112233445566778899aabbccddeeff",
     "69c4e0d86a7b0430d8cdb78070b4c55a"),
    ("AES-192", K192, "00112233445566778899aabbccddeeff",
     "dda97ca4864cdfe06eaf70a0ec0d7191"),
    ("AES-256", K256, "00112233445566778899aabbccddeeff",
     "8ea2b7ca516745bfeafc49904b496089"),
]

SP800_PT = (
    "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51"
    "30c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710"
)
SP800_IV = "000102030405060708090a0b0c0d0e0f"

SP800_ECB = [
    ("AES-128", "2b7e151628aed2a6abf7158809cf4f3c",
     "3ad77bb40d7a3660a89ecaf32466ef97f5d3d58503b9699de785895a96fdbaaf"
     "43b1cd7f598ece23881b00e3ed0306887b0c785e27e8ad3f8223207104725dd4"),
    ("AES-192", "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
     "bd334f1d6e45f25ff712a214571fa5cc974104846d0ad3ad7734ecb3ecee4eef"
     "ef7afd2270e2e60adce0ba2face6444e9a4b41ba738d6c72fb16691603c18e0e"),
    ("AES-256", "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
     "f3eed1bdb5d2a03c064b5a7e3db181f8591ccb10d410ed26dc5ba74a31362870"
     "b6ed21b99ca6f4f9f153e7b1beafed1d23304b7a39f9f3ff067d8d8f9e24ecc7"),
]

SP800_CBC = [
    ("AES-128", "2b7e151628aed2a6abf7158809cf4f3c",
     "7649abac8119b246cee98e9b12e9197d5086cb9b507219ee95db113a917678b2"
     "73bed6b8e3c1743b7116e69e222295163ff1caa1681fac09120eca307586e1a7"),
    ("AES-192", "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
     "4f021db243bc633d7178183a9fa071e8b4d9ada9ad7dedf4e5e738763f69145a"
     "571b242012fb7ae07fa9baac3df102e008b0e27988598881d920a9e64f5615cd"),
    ("AES-256", "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
     "f58c4c04d6e5f1ba779eabfb5f7bfbd69cfc4e967edb808d679f777bc6702c7d"
     "39f23369a9d9bacfa530e26304231461b2eb05e2c39be9fcda6c19078c6a9d1b"),
]


def run_single_block(kats, label):
    """Run AES on the single-block FIPS-197 KATs."""
    for name, key, pt, ct in kats:
        c = AES()
        c.generate_keys(key)
        got = c.encrypt_block(bytes.fromhex(pt))
        check(f"{label} {name.lower()} encrypt", got.hex(), ct)
        check(f"{label} {name.lower()} decrypt",
              c.decrypt_block(got).hex(), pt)


def run_mode_kats(kats, mode, label):
    """Compare multi-block mode outputs against the SP 800-38A vectors."""
    for name, key, ct in kats:
        c = AES()
        c.generate_keys(key)
        got = c.encrypt(SP800_PT, mode=mode, padding="", iv=SP800_IV)
        check(f"{label} {name.lower()} encrypt", got, ct)
        got = c.decrypt(ct, mode=mode, padding="", iv=SP800_IV)
        check(f"{label} {name.lower()} decrypt", got, SP800_PT)


def main():
    """Run AES KAT, block-mode, and padding checks."""
    print("== FIPS-197 single block ==")
    run_single_block(FIPS, "fips-197")

    print("== NIST SP 800-38A ECB (four blocks) ==")
    run_mode_kats(SP800_ECB, "ECB", "sp800-38a ecb")

    print("== NIST SP 800-38A CBC (four blocks) ==")
    run_mode_kats(SP800_CBC, "CBC", "sp800-38a cbc")

    print("== ECB multi-block round trip ==")
    for name, key in (("AES-128", K128), ("AES-192", K192), ("AES-256", K256)):
        c = AES()
        c.generate_keys(key)
        pt = "".join(f"{0xA5 + i:02x}" for i in range(32))
        ct = c.encrypt(pt, mode="ECB")
        check(f"{name}: ciphertext differs from plaintext", ct != pt, True)
        check(f"{name}: encrypt+decrypt restores plaintext",
              c.decrypt(ct, mode="ECB"), pt)

    print("== CBC two-block round trip ==")
    c = AES()
    c.generate_keys("2b7e151628aed2a6abf7158809cf4f3c")
    pt = SP800_PT[0:64]
    ct = c.encrypt(pt, mode="CBC", iv=SP800_IV)
    check("cbc two-block ciphertext differs from plaintext", ct != pt, True)
    check("cbc two-block encrypt+decrypt restores plaintext",
          c.decrypt(ct, mode="CBC", iv=SP800_IV), pt)

    print("== padding edge cases ==")
    c = AES()
    c.generate_keys(K128)
    ct = c.encrypt("ABCD", mode="ECB", padding="PKCS")
    check("2 bytes padded to one block", len(ct), 32)
    check("2 bytes round trip through PKCS padding",
          c.decrypt(ct, mode="ECB", padding="PKCS"), "abcd")
    ct = c.encrypt("", mode="ECB", padding="PKCS")
    check("empty input padded to one full block", len(ct), 32)
    pt = "".join(f"{0xA5 + i:02x}" for i in range(31))
    ct = c.encrypt(pt, mode="ECB", padding="PKCS")
    check("31 bytes padded to two blocks", len(ct), 64)
    check("31 bytes round trip through PKCS padding",
          c.decrypt(ct, mode="ECB", padding="PKCS"), pt)
    ct = c.encrypt("00112233445566778899aabbccddeeff", mode="ECB", padding="")
    check("invalid padding is not stripped",
          len(c.decrypt(ct, mode="ECB", padding="PKCS")), 32)

    print("== padding schemes (ECB/CBC round trip) ==")
    pt = "aabbccddeeff00112233"
    for pad in ("PKCS", "ANSI X9.23", "ISO 7816-4", "bit", "TBC"):
        for mode in ("ECB", "CBC"):
            c = AES()
            c.generate_keys(K128)
            iv = SP800_IV if mode == "CBC" else ""
            ct = c.encrypt(pt, mode=mode, padding=pad, iv=iv)
            check(f"{pad} {mode} round trip",
                  c.decrypt(ct, mode=mode, padding=pad, iv=iv), pt)

    print()
    print(f"{_FAILS} test(s) failed")
    return 1 if _FAILS else 0


if __name__ == "__main__":
    raise SystemExit(main())
