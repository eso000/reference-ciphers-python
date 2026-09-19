"""Cross-implementation verification harness for the teaching ciphers.

Always checks every cipher in this repo against the official published
test vectors reused from the per-cipher unit-test modules (FIPS-197 and
SP 800-38A for AES, the classic DES values, Schneier's Blowfish sets,
the Twofish AES-submission KATs, and the NESSIE/verified Serpent set).

When an external crypto library is installed it is used as a second,
independent oracle:

  pycrypto      -> AES, DES, 3DES, Blowfish
  libtomcrypt   -> Twofish
  GNU nettle    -> Serpent

Oracles that are not importable/loadable are skipped and reported as SKIP.
The script exits non-zero if any vector fails or any oracle disagrees.
"""

from typing import Callable, Dict, List, Tuple

from AES import AES
from Blowfish import Blowfish
from DES import DES, TrippleDES
from Serpent import Serpent
from Twofish import Twofish

from AESTest import FIPS as AES_VEC
from BlowfishTest import OFFICIAL as BF_VEC, SET_KEY as BF_SK
from DESTest import DES_KATS as DES_VEC
from SerpentTest import KATS as SERPENT_VEC
from TwofishTest import KATS as TF_VEC

Kats = List[Tuple[str, str, str, str]]

DES3_VEC: Kats = [
    ("3des kat", "AABB09182736CCDD123456ABCD132536c0b7a8d05f3a829c",
     "123456ABCD132536", "e6803bea92016d52"),
]
BF_SK_PT = "FEDCBA9876543210"


def named(triples: List[Tuple[str, str, str]], prefix: str) -> Kats:
    return [(prefix + " %d" % i, k, p, c)
            for i, (k, p, c) in enumerate(triples)]


def programs() -> Dict[str, Kats]:
    bf = named(BF_VEC, "official")
    bf += [("set_key %d" % (len(k) * 4), k, BF_SK_PT, c) for k, c in BF_SK]
    return {
        "AES": AES_VEC,
        "DES": named(DES_VEC, "des"),
        "DES3": DES3_VEC,
        "Blowfish": bf,
        "Twofish": named(TF_VEC, "b2"),
        "Serpent": SERPENT_VEC,
    }


PROGRAMS = programs()


def get_impl(cipher: str):
    classes = {"AES": AES, "DES": DES, "DES3": TrippleDES,
               "Blowfish": Blowfish, "Twofish": Twofish, "Serpent": Serpent}
    obj = classes[cipher]()
    return obj.generate_keys, obj.encrypt_block, obj.decrypt_block


def official_oracles() -> Dict[str, List[Tuple[str, Callable, Callable]]]:
    found: Dict[str, List[Tuple[str, Callable, Callable]]] = {}
    try:
        from Crypto.Cipher import AES as _AES, DES as _DES, DES3 as _DES3
        from Crypto.Cipher import Blowfish as _BF

        def ecb(mod):
            def enc(key: bytes, pt: bytes) -> str:
                return mod.new(key, mod.MODE_ECB).encrypt(pt).hex()

            def dec(key: bytes, ct: bytes) -> str:
                return mod.new(key, mod.MODE_ECB).decrypt(ct).hex()

            return enc, dec

        for name, mod in (("AES", _AES), ("DES", _DES),
                          ("DES3", _DES3), ("Blowfish", _BF)):
            enc, dec = ecb(mod)
            found[name] = [("pycrypto", enc, dec)]
    except ImportError:
        pass

    try:
        import ctypes
        tom = ctypes.CDLL("libtomcrypt.so.1")
        ctx = ctypes.create_string_buffer(16384)

        def tf_enc(key: bytes, pt: bytes) -> str:
            k = ctypes.create_string_buffer(key)
            p = ctypes.create_string_buffer(pt)
            o = ctypes.create_string_buffer(16)
            if tom.twofish_setup(k, len(key), 0, ctx) != 0:
                raise RuntimeError("twofish_setup failed")
            tom.twofish_ecb_encrypt(p, o, ctx)
            return o.raw.hex()

        def tf_dec(key: bytes, ct: bytes) -> str:
            k = ctypes.create_string_buffer(key)
            c = ctypes.create_string_buffer(ct)
            o = ctypes.create_string_buffer(16)
            if tom.twofish_setup(k, len(key), 0, ctx) != 0:
                raise RuntimeError("twofish_setup failed")
            tom.twofish_ecb_decrypt(c, o, ctx)
            return o.raw.hex()

        found["Twofish"] = [("libtomcrypt", tf_enc, tf_dec)]
    except (ImportError, OSError):
        pass

    try:
        import ctypes
        net = ctypes.CDLL("libnettle.so.8")
        ser = ctypes.create_string_buffer(16384)

        def ser_enc(key: bytes, pt: bytes) -> str:
            k = ctypes.create_string_buffer(key)
            p = ctypes.create_string_buffer(pt)
            o = ctypes.create_string_buffer(16)
            net.nettle_serpent_set_key(ser, len(key), k)
            net.nettle_serpent_encrypt(ser, 16, o, p)
            return o.raw.hex()

        def ser_dec(key: bytes, ct: bytes) -> str:
            k = ctypes.create_string_buffer(key)
            c = ctypes.create_string_buffer(ct)
            o = ctypes.create_string_buffer(16)
            net.nettle_serpent_set_key(ser, len(key), k)
            net.nettle_serpent_decrypt(ser, 16, o, c)
            return o.raw.hex()

        found["Serpent"] = [("nettle", ser_enc, ser_dec)]
    except (ImportError, OSError):
        pass

    return found


def run(cipher: str) -> Tuple[str, List[str]]:
    make_keys, enc_block, dec_block = get_impl(cipher)
    vecs = PROGRAMS[cipher]
    reports: List[str] = []
    passed = 0
    for name, key, pt, ct in vecs:
        make_keys(key)
        got = enc_block(bytes.fromhex(pt)).hex()
        got_d = dec_block(bytes.fromhex(ct)).hex()
        ok = got.lower() == ct.lower() and got_d.lower() == pt.lower()
        passed += ok
        if not ok:
            reports.append("  FAIL %-20s enc=%s dec=%s want=%s"
                           % (name, got, got_d, ct))
    line = "  in-repo  : %d/%d passed" % (passed, len(vecs))
    oracles = official_oracles().get(cipher, [])
    for label, enc, dec in oracles:
        results = []
        for name, key, pt, ct in vecs:
            try:
                enc_ok = enc(bytes.fromhex(key), bytes.fromhex(pt)) == ct.lower()
                dec_ok = dec(bytes.fromhex(key), bytes.fromhex(ct)) == pt.lower()
            except Exception:
                enc_ok = dec_ok = False
            results.append(enc_ok and dec_ok)
        n_ok = sum(results)
        line += "\n  %-11s: %d/%d passed" % (label, n_ok, len(vecs))
        if n_ok != len(vecs):
            bad = [vecs[i][0] for i, ok in enumerate(results) if not ok]
            reports.append("  %s FAILED vectors: %s" % (label, ", ".join(bad)))
    if not oracles:
        line += "\n  oracles  : SKIP (no library for this cipher installed)"
    return line, reports


def main() -> int:
    failures = 0
    for cipher in ("AES", "DES", "DES3", "Blowfish", "Twofish", "Serpent"):
        print("== %s ==" % cipher)
        line, reports = run(cipher)
        print(line)
        for r in reports:
            print(r)
        if reports:
            failures += 1
        print()
    if failures:
        print("FAILURES: %d cipher(s) have failing vectors" % failures)
        return 1
    print("ALL VECTORS PASSED for in-repo ciphers and all detected oracles")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())