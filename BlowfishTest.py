"""Blowfish known-answer, block-mode, and padding tests.

Vectors: Schneier's full 34-entry official ECB set plus the 24 official
``set_key`` vectors covering 1- to 24-byte keys (the key schedules cycle
short keys), and the repository's own KAT.
"""

from Blowfish import Blowfish

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


OFFICIAL = [
    ("0000000000000000", "0000000000000000", "4EF997456198DD78"),
    ("FFFFFFFFFFFFFFFF", "FFFFFFFFFFFFFFFF", "51866FD5B85ECB8A"),
    ("3000000000000000", "1000000000000001", "7D856F9A613063F2"),
    ("1111111111111111", "1111111111111111", "2466DD878B963C9D"),
    ("0123456789ABCDEF", "1111111111111111", "61F9C3802281B096"),
    ("1111111111111111", "0123456789ABCDEF", "7D0CC630AFDA1EC7"),
    ("0000000000000000", "0000000000000000", "4EF997456198DD78"),
    ("FEDCBA9876543210", "0123456789ABCDEF", "0ACEAB0FC6A0A28D"),
    ("7CA110454A1A6E57", "01A1D6D039776742", "59C68245EB05282B"),
    ("0131D9619DC1376E", "5CD54CA83DEF57DA", "B1B8CC0B250F09A0"),
    ("07A1133E4A0B2686", "0248D43806F67172", "1730E5778BEA1DA4"),
    ("3849674C2602319E", "51454B582DDF440A", "A25E7856CF2651EB"),
    ("04B915BA43FEB5B6", "42FD443059577FA2", "353882B109CE8F1A"),
    ("0113B970FD34F2CE", "059B5E0851CF143A", "48F4D0884C379918"),
    ("0170F175468FB5E6", "0756D8E0774761D2", "432193B78951FC98"),
    ("43297FAD38E373FE", "762514B829BF486A", "13F04154D69D1AE5"),
    ("07A7137045DA2A16", "3BDD119049372802", "2EEDDA93FFD39C79"),
    ("04689104C2FD3B2F", "26955F6835AF609A", "D887E0393C2DA6E3"),
    ("37D06BB516CB7546", "164D5E404F275232", "5F99D04F5B163969"),
    ("1F08260D1AC2465E", "6B056E18759F5CCA", "4A057A3B24D3977B"),
    ("584023641ABA6176", "004BD6EF09176062", "452031C1E4FADA8E"),
    ("025816164629B007", "480D39006EE762F2", "7555AE39F59B87BD"),
    ("49793EBC79B3258F", "437540C8698F3CFA", "53C55F9CB49FC019"),
    ("4FB05E1515AB73A7", "072D43A077075292", "7A8E7BFA937E89A3"),
    ("49E95D6D4CA229BF", "02FE55778117F12A", "CF9C5D7A4986ADB5"),
    ("018310DC409B26D6", "1D9D5C5018F728C2", "D1ABB290658BC778"),
    ("1C587F1C13924FEF", "305532286D6F295A", "55CB3774D13EF201"),
    ("0101010101010101", "0123456789ABCDEF", "FA34EC4847B268B2"),
    ("1F1F1F1F0E0E0E0E", "0123456789ABCDEF", "A790795108EA3CAE"),
    ("E0FEE0FEF1FEF1FE", "0123456789ABCDEF", "C39E072D9FAC631D"),
    ("0000000000000000", "FFFFFFFFFFFFFFFF", "014933E0CDAFF6E4"),
    ("FFFFFFFFFFFFFFFF", "0000000000000000", "F21E9A77B71C49BC"),
    ("0123456789ABCDEF", "0000000000000000", "245946885754369A"),
    ("FEDCBA9876543210", "FFFFFFFFFFFFFFFF", "6B5C5A9C5D9E0A5A"),
]

SET_KEY = [
    ("F0", "F9AD597C49DB005E"),
    ("F0E1", "E91D21C1D961A6D6"),
    ("F0E1D2", "E9C2B70A1BC65CF3"),
    ("F0E1D2C3", "BE1E639408640F05"),
    ("F0E1D2C3B4", "B39E44481BDB1E6E"),
    ("F0E1D2C3B4A5", "9457AA83B1928C0D"),
    ("F0E1D2C3B4A596", "8BB77032F960629D"),
    ("F0E1D2C3B4A59687", "E87A244E2CC85E82"),
    ("F0E1D2C3B4A5968778", "15750E7A4F4EC577"),
    ("F0E1D2C3B4A596877869", "122BA70B3AB64AE0"),
    ("F0E1D2C3B4A5968778695A", "3A833C9AFFC537F6"),
    ("F0E1D2C3B4A5968778695A4B", "9409DA87A90F6BF2"),
    ("F0E1D2C3B4A5968778695A4B3C", "884F80625060B8B4"),
    ("F0E1D2C3B4A5968778695A4B3C2D", "1F85031C19E11968"),
    ("F0E1D2C3B4A5968778695A4B3C2D1E", "79D9373A714CA34F"),
    ("F0E1D2C3B4A5968778695A4B3C2D1E0F", "93142887EE3BE15C"),
    ("F0E1D2C3B4A5968778695A4B3C2D1E0F00", "03429E838CE2D14B"),
    ("F0E1D2C3B4A5968778695A4B3C2D1E0F0011", "A4299E27469FF67B"),
    ("F0E1D2C3B4A5968778695A4B3C2D1E0F001122", "AFD5AED1C1BC96A8"),
    ("F0E1D2C3B4A5968778695A4B3C2D1E0F00112233", "10851C0E3858DA9F"),
    ("F0E1D2C3B4A5968778695A4B3C2D1E0F0011223344", "E6F51ED79B9DB21F"),
    ("F0E1D2C3B4A5968778695A4B3C2D1E0F001122334455", "64A6E14AFD36B46F"),
    ("F0E1D2C3B4A5968778695A4B3C2D1E0F00112233445566", "80C7D7D45A5479AD"),
    ("F0E1D2C3B4A5968778695A4B3C2D1E0F0011223344556677", "05044B62FA52D080"),
]


def run_official():
    """Run Schneier's 34-entry official ECB KAT set."""
    for i, (key, pt, ct) in enumerate(OFFICIAL):
        name = f"official ecb {i + 1:02d}"
        c = Blowfish()
        c.generate_keys(bytes.fromhex(key))
        got = c.encrypt_block(bytes.fromhex(pt))
        check(name + " encrypt", got.hex(), ct)
        check(name + " decrypt", c.decrypt_block(got).hex(), pt)


def run_set_key():
    """Run the 24 set_key vectors covering 1- to 24-byte keys."""
    for key, ct in SET_KEY:
        c = Blowfish()
        c.generate_keys(bytes.fromhex(key))
        name = f"set_key {len(key) // 2}-byte key"
        check(name, c.encrypt_block(bytes.fromhex("FEDCBA9876543210")).hex(), ct)


def main():
    """Run Blowfish KAT, mode, key-ring, and padding checks."""
    print("== Blowfish official ECB vectors ==")
    run_official()

    print("== Blowfish official set_key vectors ==")
    run_set_key()

    c = Blowfish()
    c.generate_keys(bytes.fromhex("AABB09182736CCDD"))
    check("repo vector: key=AABB09182736CCDD -> c8fdcaea64fa2c82",
          c.encrypt_block(bytes.fromhex("123456ABCD132536")).hex(), "c8fdcaea64fa2c82")

    print("== ECB multi-block round trip ==")
    c = Blowfish()
    c.generate_keys(bytes.fromhex("0123456789abcdef"))
    pt = bytes(0xA5 + i for i in range(24))
    ct = c.encrypt(pt, mode="ECB")
    check("ecb ciphertext differs from plaintext", ct != pt, True)
    check("ecb encrypt+decrypt restores plaintext", c.decrypt(ct, mode="ECB"), pt)

    print("== CBC round trip ==")
    c = Blowfish()
    c.generate_keys(bytes.fromhex("0123456789abcdef"))
    pt = bytes(range(16))
    iv = bytes.fromhex("1122334455667788")
    ct = c.encrypt(pt, mode="CBC", iv=iv)
    check("cbc ciphertext differs from plaintext", ct != pt, True)
    check("cbc encrypt+decrypt restores plaintext",
          c.decrypt(ct, mode="CBC", iv=iv), pt)

    print("== PKCS#7 padding ==")
    c = Blowfish()
    c.generate_keys(bytes.fromhex("00112233445566778899aabbccddeeff"))
    pt = bytes.fromhex("123456abcdcd13")
    ct = c.encrypt(pt, mode="ECB", padding="PKCS")
    check("7-byte input padded to one block", len(ct), 8)
    check("7-byte input round trip through PKCS padding",
          c.decrypt(ct, mode="ECB", padding="PKCS"), pt)
    ct = c.encrypt(bytes.fromhex("123456abcdcd1301"), mode="ECB", padding="PKCS")
    check("block-aligned input gets a full extra padding block", len(ct), 16)
    ct = c.encrypt(b"", mode="ECB", padding="PKCS")
    check("empty input padded to one full block", len(ct), 8)
    ct = c.encrypt(bytes.fromhex("123456abcdcd13ff"), mode="ECB", padding="")
    check("invalid padding is rejected",
          raises_value_error(lambda: c.decrypt(ct, mode="ECB", padding="PKCS")), True)

    print("== standard key schedule (non-aligned key lengths) ==")
    for label, key in (("3-byte", "AABBCC"),
                       ("56-byte (max)", "".join(f"{((i * 37) % 256):02x}" for i in range(56)))):
        c = Blowfish()
        c.generate_keys(bytes.fromhex(key))
        pt = "123456abcd132536"
        ct = c.encrypt_block(bytes.fromhex(pt)).hex()
        check(f"{label} key: ciphertext differs from plaintext", ct != pt, True)
        check(f"{label} key: encrypt+decrypt restores plaintext",
              c.decrypt_block(bytes.fromhex(ct)).hex(), pt)

    print("== key length validation ==")
    for label, key in (("empty key rejected", ""),
                       ("57-byte key rejected", "".join(f"{i % 256:02x}" for i in range(57)))):
        try:
            Blowfish().generate_keys(bytes.fromhex(key))
            check(label, False, True)
        except ValueError:
            check(label, True, True)

    print()
    print(f"{_FAILS} test(s) failed")
    return 1 if _FAILS else 0


if __name__ == "__main__":
    raise SystemExit(main())
