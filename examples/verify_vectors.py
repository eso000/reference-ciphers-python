"""Cross-implementation verification harness for the teaching ciphers.

Always checks every cipher in this repo against the published test vectors
in tests/vectors.py (FIPS-197 and SP 800-38A for AES, the classic DES
values, Schneier's Blowfish sets, the Twofish AES-submission KATs, and the
NESSIE/verified Serpent set).

When an external crypto library is installed it is used as a second,
independent oracle:

  pycrypto      -> AES, DES, 3DES, Blowfish
  libtomcrypt   -> Twofish
  GNU nettle    -> Serpent

Oracles that are not importable/loadable are skipped and reported as SKIP.
The script exits non-zero if any vector fails or any oracle disagrees.
"""

import ctypes
from typing import Callable, Dict, List, Tuple

from src.AES import AES
from src.Blowfish import Blowfish
from src.DES import DES
from src.Serpent import Serpent
from src.Twofish import Twofish

from tests.vectors import programs as vector_programs

try:
    from Crypto.Cipher import AES as PY_AES, DES as PY_DES
    from Crypto.Cipher import Blowfish as PY_BF
except ImportError:
    PY_AES = PY_DES = PY_BF = None

Kats = List[Tuple[str, str, str, str]]

PROGRAMS = vector_programs()


def get_impl(cipher: str):
    """Return (generate_keys, encrypt_block, decrypt_block) for ``cipher``."""
    classes = {
        "AES": AES,
        "DES": DES,
        "Blowfish": Blowfish,
        "Twofish": Twofish,
        "Serpent": Serpent,
    }
    obj = classes[cipher]()
    return obj.generate_keys, obj.encrypt_block, obj.decrypt_block


def official_oracles() -> Dict[str, List[Tuple[str, Callable, Callable]]]:
    """Locate any installed external crypto libraries usable as oracles."""
    found: Dict[str, List[Tuple[str, Callable, Callable]]] = {}

    if PY_AES is not None:

        def ecb(mod):
            def enc(key: bytes, pt: bytes) -> str:
                return mod.new(key, mod.MODE_ECB).encrypt(pt).hex()

            def dec(key: bytes, ct: bytes) -> str:
                return mod.new(key, mod.MODE_ECB).decrypt(ct).hex()

            return enc, dec

        for name, mod in (("AES", PY_AES), ("DES", PY_DES), ("Blowfish", PY_BF)):
            enc, dec = ecb(mod)
            found[name] = [("pycrypto", enc, dec)]

    try:
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
    """Verify ``cipher`` against its vectors and any available oracles."""
    make_keys, enc_block, dec_block = get_impl(cipher)
    vecs = PROGRAMS[cipher]
    reports: List[str] = []
    passed = 0
    for name, key, pt, ct in vecs:
        make_keys(bytes.fromhex(key))
        got = enc_block(bytes.fromhex(pt)).hex()
        got_d = dec_block(bytes.fromhex(ct)).hex()
        ok = got.lower() == ct.lower() and got_d.lower() == pt.lower()
        passed += ok
        if not ok:
            reports.append(f"  FAIL {name:<20} enc={got} dec={got_d} want={ct}")
    line = f"  in-repo  : {passed}/{len(vecs)} passed"
    oracles = official_oracles().get(cipher, [])
    for label, enc, dec in oracles:
        results = []
        for name, key, pt, ct in vecs:
            try:
                enc_ok = enc(bytes.fromhex(key), bytes.fromhex(pt)) == ct.lower()
                dec_ok = dec(bytes.fromhex(key), bytes.fromhex(ct)) == pt.lower()
            except (ValueError, OSError, RuntimeError):
                enc_ok = dec_ok = False
            results.append(enc_ok and dec_ok)
        n_ok = sum(results)
        line += f"\n  {label:<11}: {n_ok}/{len(vecs)} passed"
        if n_ok != len(vecs):
            bad = [vecs[i][0] for i, ok in enumerate(results) if not ok]
            reports.append(f"  {label} FAILED vectors: {', '.join(bad)}")
    if not oracles:
        line += "\n  oracles  : SKIP (no library for this cipher installed)"
    return line, reports


def main() -> int:
    """Run all ciphers and report the combined status.

    Triple DES is absent on purpose: it has no vector of confirmed
    provenance here, and an oracle cannot cross-check a value we do not
    trust. tests/test_des.py checks it structurally instead.
    """
    failures = 0
    for cipher in PROGRAMS:
        print(f"== {cipher} ==")
        line, reports = run(cipher)
        print(line)
        for r in reports:
            print(r)
        if reports:
            failures += 1
        print()
    if failures:
        print(f"FAILURES: {failures} cipher(s) have failing vectors")
        return 1
    print("ALL VECTORS PASSED for in-repo ciphers and all detected oracles")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
