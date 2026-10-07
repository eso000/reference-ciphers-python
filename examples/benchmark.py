"""Throughput benchmark for the block ciphers in this repo.

Times every cipher in every block mode that ``EncryptionBase`` implements, in
both directions, and compares the pure-Python implementations against any
installed native crypto library that offers the same cipher.

Run from the repository root so that the ``src`` package is importable::

    python3 -m examples.benchmark
    python3 -m examples.benchmark --rounds 9 --bytes 65536
    python3 -m examples.benchmark --json

Reading the numbers
-------------------
* ``KB/s`` is always measured over the bytes the call *actually* processed,
  which for the padded modes (ECB, CBC, PCBC) includes the padding block.
* Each figure is the **best** of ``--rounds`` timed runs after one warm-up
  run. The minimum is the least noisy estimator here: it is the run least
  disturbed by scheduler preemption and garbage collection.
* Native figures are labelled with how they were obtained. A bulk call is
  genuinely faster than a per-block call from Python, so a ``ctypes`` oracle
  that loops one block at a time is dominated by the FFI call overhead and
  says more about ctypes than about the cipher. Compare those with care.
* Absolute figures are machine- and build-specific. Only the ordering and the
  ratios between two rows of the same run are meaningful.
"""

import argparse
import ctypes
import json
import platform
import sys
import time

from src.AES import AES
from src.Blowfish import Blowfish
from src.DES import DES, TripleDES
from src.Serpent import Serpent
from src.Twofish import Twofish

try:
    from Crypto.Cipher import AES as PY_AES, Blowfish as PY_BF
    from Crypto.Cipher import DES as PY_DES, DES3 as PY_DES3
except ImportError:  # pragma: no cover - depends on what is installed
    PY_AES = PY_BF = PY_DES = PY_DES3 = None


# One key per cipher, sized to what that cipher accepts. AES, Serpent and
# Twofish all take 16/24/32 bytes; 32 is used here because it is the most
# expensive key schedule of the three, which is the pessimistic case.
KEYS = {
    "DES": "0011223344556677",
    "TripleDES": "00112233445566778899aabbccddeeff0011223344556677",
    "Blowfish": "00112233445566778899aabbccddeeff",
    "AES": "000102030405060708090a0b0c0d0e0f",
    "Serpent": "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
    "Twofish": "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
}

CIPHERS = [DES, TripleDES, Blowfish, AES, Serpent, Twofish]

# Every mode the base class implements. ECB rejects an IV; the rest need one.
MODES = ["ECB", "CBC", "PCBC", "CFB", "OFB", "CTR"]

# Scratch buffers shared by the per-block ctypes loops, so a measurement is not
# charged for allocating a fresh pair of buffers on every block. The FFI entry
# points overwrite the whole 16-byte destination on every call, so no stale
# data can leak from one block into the next.
_CTYPES_SRC = ctypes.create_string_buffer(16)
_CTYPES_DST = ctypes.create_string_buffer(16)


class NativeOracle:
    """An ECB oracle backed by an installed native crypto library.

    ``granularity`` records how the native code is driven, because it decides
    whether the figure is a fair speed comparison:

    ``"bulk"``
        the whole buffer is handed to the native library in one call, which is
        what a real application does and what this repo's pure-Python loop is
        competing with.
    ``"block"``
        one block per FFI call, because the native API exposes no bulk ECB
        entry point. The result is dominated by ctypes overhead.
    """

    

    def __init__(self, name, library, block_size, granularity, enc, dec):
        self.name = name
        self.library = library
        self.block_size = block_size
        self.granularity = granularity
        self._enc = enc
        self._dec = dec

    def encrypt(self, data):
        """ECB-encrypt ``data`` with the native implementation."""
        return self._enc(data)

    def decrypt(self, data):
        """ECB-decrypt ``data`` with the native implementation."""
        return self._dec(data)


def best_of(call, rounds):
    """Return the shortest wall-clock time of ``rounds`` runs of ``call``.

    One untimed warm-up run comes first so that import-time lazy work and the
    first-touch page faults are not charged to the measurement. ``perf_counter``
    is used rather than ``time.time``: it is monotonic, so a clock adjustment
    during the run cannot produce a negative or wildly long interval.
    """
    call()
    best = float("inf")
    for _ in range(rounds):
        start = time.perf_counter()
        call()
        best = min(best, time.perf_counter() - start)
    return best


def rate(nbytes, seconds):
    """Bytes per second, expressed in KB/s (1 KB = 1000 bytes)."""
    return nbytes / seconds / 1000 if seconds > 0 else float("inf")


def padded_size(nbytes, block_size):
    """Bytes actually fed to the cipher for an unpadded request of ``nbytes``.

    The padded modes always append padding, including a whole block when the
    input is already aligned, so throughput must be computed over the padded
    length or the reported rate is quietly overstated.
    """
    return nbytes + block_size - nbytes % block_size


def measure_cipher(cls, data, rounds, modes):
    """Time one cipher: key setup, raw block calls, and every mode.

    Returns a dict of measurements. ``encrypt_kbs``/``decrypt_kbs`` are keyed
    by mode name; ``block_*`` isolates the raw ``encrypt_block`` cost so that
    mode overhead can be read off directly by comparing the two.
    """
    obj = cls()
    block_size = obj.block_size
    key = bytes.fromhex(KEYS[cls.__name__])
    obj.generate_keys(key)

    out = {"block_size": block_size, "key_bytes": len(key)}

    # Key setup is a per-key cost, not a throughput, so it is reported as
    # operations per second. Blowfish's is the notable one: it derives all
    # 4168 bytes of its P-array and S-boxes from the key material.
    seconds = best_of(lambda: obj.generate_keys(key), rounds)
    out["key_setup_per_sec"] = 1 / seconds if seconds > 0 else float("inf")
    obj.generate_keys(key)

    # Raw single-block cost with no mode logic at all.
    one_block = data[:block_size]
    seconds = best_of(lambda: obj.encrypt_block(one_block), rounds)
    out["block_encrypt_kbs"] = rate(block_size, seconds)
    seconds = best_of(lambda: obj.decrypt_block(one_block), rounds)
    out["block_decrypt_kbs"] = rate(block_size, seconds)

    out["modes"] = {}
    for mode in modes:
        entry = {}
        iv = b"" if mode == "ECB" else bytes(block_size)

        ciphertext = obj.encrypt(data, mode=mode, iv=iv)
        entry["bytes"] = len(ciphertext)
        seconds = best_of(
            lambda m=mode, i=iv: obj.encrypt(data, mode=m, iv=i), rounds
        )
        entry["encrypt_kbs"] = rate(len(ciphertext), seconds)

        seconds = best_of(
            lambda m=mode, i=iv, c=ciphertext: obj.decrypt(c, mode=m, iv=i), rounds
        )
        entry["decrypt_kbs"] = rate(len(ciphertext), seconds)
        out["modes"][mode] = entry

    return out


def native_oracles():
    """Return the native ECB oracles available on this machine.

    Missing libraries are simply absent from the result, so the caller can
    report them as skipped without treating them as failures.
    """
    oracles = []

    if PY_AES is not None:
        for name, module, cls in (
            ("AES", PY_AES, AES),
            ("DES", PY_DES, DES),
            ("TripleDES", PY_DES3, TripleDES),
            ("Blowfish", PY_BF, Blowfish),
        ):
            key = bytes.fromhex(KEYS[name])
            cipher = module.new(key, module.MODE_ECB)
            oracles.append(
                NativeOracle(
                    name,
                    "pycryptodome",
                    cls.block_size,
                    "bulk",
                    cipher.encrypt,
                    cipher.decrypt,
                )
            )

    # nettle and libtomcrypt expose only single-block ECB entry points, so they
    # are driven one block at a time. That is an FFI-bound figure, not a
    # cipher-bound one, and is labelled as such.
    try:
        nettle = ctypes.CDLL("libnettle.so.8")
        key = bytes.fromhex(KEYS["Serpent"])
        ctx = ctypes.create_string_buffer(16384)
        nettle.nettle_serpent_set_key(ctx, len(key), key)

        def serpent_stream(data, decrypt=False):
            """Drive nettle's single-block ECB entry point over ``data``.

            Buffers are allocated once and reused, so the figure reflects the
            cost of the FFI call and the cipher rather than per-block buffer
            allocation.
            """
            out = bytearray()
            fn = (
                nettle.nettle_serpent_decrypt
                if decrypt
                else nettle.nettle_serpent_encrypt
            )
            src, dst = _CTYPES_SRC, _CTYPES_DST
            for i in range(0, len(data), 16):
                ctypes.memmove(src, data[i : i + 16], 16)
                fn(ctx, 16, dst, src)
                out.extend(dst.raw)
            return bytes(out)

        oracles.append(
            NativeOracle(
                "Serpent",
                "nettle",
                16,
                "block",
                serpent_stream,
                lambda d: serpent_stream(d, decrypt=True),
            )
        )
    except (ImportError, OSError):
        pass

    try:
        tom = ctypes.CDLL("libtomcrypt.so.1")
        key = bytes.fromhex(KEYS["Twofish"])
        ctx = ctypes.create_string_buffer(16384)
        tom.twofish_setup(key, len(key), 0, ctx)

        def twofish_stream(data, decrypt=False):
            """Drive libtomcrypt's single-block ECB entry point over ``data``."""
            out = bytearray()
            fn = tom.twofish_ecb_decrypt if decrypt else tom.twofish_ecb_encrypt
            src, dst = _CTYPES_SRC, _CTYPES_DST
            for i in range(0, len(data), 16):
                ctypes.memmove(src, data[i : i + 16], 16)
                fn(src, dst, ctx)
                out.extend(dst.raw)
            return bytes(out)

        oracles.append(
            NativeOracle(
                "Twofish",
                "libtomcrypt",
                16,
                "block",
                twofish_stream,
                lambda d: twofish_stream(d, decrypt=True),
            )
        )
    except (ImportError, OSError):
        pass

    return oracles


def measure_native(oracle, data, rounds):
    """Time a native oracle over the same message the pure-Python side used."""
    ciphertext = oracle.encrypt(data)
    seconds = best_of(lambda: oracle.encrypt(data), rounds)
    enc_kbs = rate(len(ciphertext), seconds)
    seconds = best_of(lambda: oracle.decrypt(ciphertext), rounds)
    dec_kbs = rate(len(ciphertext), seconds)
    return {
        "library": oracle.library,
        "granularity": oracle.granularity,
        "bytes": len(ciphertext),
        "encrypt_kbs": enc_kbs,
        "decrypt_kbs": dec_kbs,
    }


def parse_args(argv):
    """Parse the command line."""
    parser = argparse.ArgumentParser(
        description="Throughput benchmark for the repo's block ciphers.",
        epilog="Run from the repository root: python3 -m examples.benchmark",
    )
    parser.add_argument(
        "--bytes",
        type=int,
        default=4000,
        help="message size in bytes (default: 4000)",
    )
    parser.add_argument(
        "--rounds",
        type=int,
        default=5,
        help="timed runs per measurement; the fastest is reported "
        "(default: 5)",
    )
    parser.add_argument(
        "--mode",
        action="append",
        dest="modes",
        choices=MODES,
        help="restrict to this mode; repeatable (default: all)",
    )
    parser.add_argument(
        "--cipher",
        action="append",
        dest="ciphers",
        choices=sorted(KEYS),
        help="restrict to this cipher; repeatable (default: all)",
    )
    parser.add_argument(
        "--no-native",
        action="store_true",
        help="skip the installed native libraries",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="emit the raw measurements as JSON instead of a table",
    )
    return parser.parse_args(argv)


def report(results, natives, args, data):
    """Print the human-readable table.

    ``results`` maps a cipher name to its pure-Python measurements and
    ``natives`` maps a cipher name to its native measurements.
    """
    print(
        f"Block cipher throughput: {len(data)} bytes, "
        f"best of {args.rounds} run(s), "
        f"Python {platform.python_version()} on {platform.system()}"
    )
    print("Pure-Python implementations, KB/s")
    print()
    header = (
        f"{'cipher':<10} {'block':>5} {'key':>4} "
        f"{'key setup':>12} {'raw enc':>9} {'raw dec':>9}"
    )
    print(header)
    print("-" * len(header))
    for cls in CIPHERS:
        if args.ciphers and cls.__name__ not in args.ciphers:
            continue
        r = results[cls.__name__]
        print(
            f"{cls.__name__:<10} {r['block_size']:>5} {r['key_bytes']:>4} "
            f"{r['key_setup_per_sec']:>10.0f}/s {r['block_encrypt_kbs']:>9.1f} "
            f"{r['block_decrypt_kbs']:>9.1f}"
        )

    print()
    print("By mode, KB/s (raw = encrypt_block with no mode logic)")
    for cls in CIPHERS:
        if args.ciphers and cls.__name__ not in args.ciphers:
            continue
        r = results[cls.__name__]
        print()
        print(f"  {cls.__name__}")
        for mode, entry in r["modes"].items():
            print(
                f"    {mode:<5} enc {entry['encrypt_kbs']:>9.1f}   "
                f"dec {entry['decrypt_kbs']:>9.1f}   "
                f"({entry['bytes']} bytes)"
            )

    if natives:
        print()
        print("Native libraries, ECB only, KB/s")
        print(
            "  'bulk' = one native call for the whole message; "
            "'block' = one FFI call per block (overhead-dominated)"
        )
        print()
        for name, n in natives.items():
            mine = results.get(name, {}).get("modes", {}).get("ECB", {})
            print(
                f"  {name:<10} {n['library']:<13} "
                f"[{n['granularity']}] enc {n['encrypt_kbs']:>10.1f}   "
                f"dec {n['decrypt_kbs']:>10.1f}"
            )
            if mine and mine["encrypt_kbs"] > 0:
                print(
                    f"  {'':<10} {'this repo':<13} "
                    f"[pure-Python] enc {mine['encrypt_kbs']:>10.1f}   "
                    f"dec {mine['decrypt_kbs']:>10.1f}   "
                    f"-> native is "
                    f"{n['encrypt_kbs'] / mine['encrypt_kbs']:.1f}x the encrypt rate"
                )


def main(argv=None):
    """Run the benchmark and return a process exit code."""
    args = parse_args(argv if argv is not None else sys.argv[1:])
    if args.bytes <= 0 or args.rounds <= 0:
        print("--bytes and --rounds must be positive", file=sys.stderr)
        return 2

    modes = args.modes or MODES
    data = bytes(args.bytes)
    results = {}
    for cls in CIPHERS:
        if args.ciphers and cls.__name__ not in args.ciphers:
            continue
        results[cls.__name__] = measure_cipher(cls, data, args.rounds, modes)

    # The native side is driven over ECB, because that is the one mode every
    # oracle here can express. Its message is padded the same way the pure
    # Python ECB path pads, so the byte counts line up.
    natives = {}
    if not args.no_native:
        # ECB is the mode every oracle here can express, so the native side is
        # driven over ECB alone and the message is pre-padded to exactly the
        # byte count the pure-Python ECB path will process. That keeps the two
        # sides measuring the same number of bytes.
        padded = {
            name: bytes(padded_size(args.bytes, r["block_size"]))
            for name, r in results.items()
        }
        for oracle in native_oracles():
            if args.ciphers and oracle.name not in args.ciphers:
                continue
            if oracle.name not in padded:
                continue
            natives[oracle.name] = measure_native(
                oracle, padded[oracle.name], args.rounds
            )

    if args.json:
        print(
            json.dumps(
                {
                    "python": platform.python_version(),
                    "platform": platform.system(),
                    "bytes": args.bytes,
                    "rounds": args.rounds,
                    "ciphers": results,
                    "native": natives,
                },
                indent=2,
                sort_keys=True,
            )
        )
    else:
        report(results, natives, args, data)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
