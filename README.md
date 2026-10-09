# Cryptology (Python)

![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue)
![License: MIT](https://img.shields.io/badge/license-MIT-green)
![Dependencies: none](https://img.shields.io/badge/dependencies-none-brightgreen)

From-scratch, dependency-free implementations of six classic block ciphers in
pure Python — written to be read. Every primitive is spelled out step by step,
and every cipher is checked against the official published test vectors, against
an independent implementation of the same math, and, where available, against a
third-party crypto library used as an oracle.

## Background

AES and DES have no shortage of reference implementations to check against. The
other ciphers are less forgiving: with fewer trustworthy references, getting
them right took far more rigorous debugging. This repo grew out of that — one
clean, from-scratch implementation per cipher, plus a test suite strict enough
to demonstrate correctness rather than merely assert it.

## Highlights

- **Six ciphers, zero dependencies** — AES, DES, 3DES, Blowfish, Twofish and
  Serpent, all in pure standard-library Python 3.10+.
- **Verified three ways** — published known-answer vectors, two independent
  implementations cross-checked against each other (DES/3DES and Serpent), and
  external crypto libraries (pycryptodome, libtomcrypt, nettle) used as
  independent oracles.
- **Six block modes** — ECB, CBC, PCBC, CFB, OFB and CTR, shared by every cipher
  through a single base class.
- **Strict, predictable API** — bytes in, bytes out; wrong lengths raise
  `ValueError`, hex strings raise `TypeError`, and nothing is silently adjusted.
- **Written to be read** — internals follow the specifications rather than
  micro-optimized tricks.

## Ciphers

| Cipher    | Block size | Key sizes        | Standard / source                     |
|-----------|-----------:|------------------|---------------------------------------|
| AES       | 128 bit    | 128 / 192 / 256  | FIPS-197                              |
| DES       | 64 bit     | 56 bit (+parity) | FIPS 46-3                             |
| 3DES      | 64 bit     | 168 bit (EDE)    | NIST SP 800-67                        |
| Blowfish  | 64 bit     | 32–448 bit       | Bruce Schneier, 1993                  |
| Twofish   | 128 bit    | 128 / 192 / 256  | AES submission (Schneier et al.)      |
| Serpent   | 128 bit    | 128 / 192 / 256  | NESSIE finalist (Anderson et al.)     |

## Quick start

Run from the repository root; the `src` package is imported directly, so there is
no install step:

```python
from src import AES

c = AES()
c.generate_keys(bytes.fromhex("000102030405060708090a0b0c0d0e0f"))
c.encrypt_block(bytes.fromhex("00112233445566778899aabbccddeeff")).hex()
# '69c4e0d86a7b0430d8cdb78070b4c55a'
```

For whole messages, `encrypt` / `decrypt` handle any length. The default mode is
CBC with ISO 7816-4 padding:

```python
import os

iv = os.urandom(16)                      # fresh, unpredictable, one block long
ct = c.encrypt(b"attack at dawn", mode="CBC", padding="ISO 7816-4", iv=iv)
pt = c.decrypt(ct, mode="CBC", padding="ISO 7816-4", iv=iv)
# b'attack at dawn'
```

## Architecture

All ciphers share one base class, `EncryptionBase` in
`src/encryption_base.py`. It provides the common building blocks (byte-level
XOR, bit permutations, rotations, padding) and the block-mode `encrypt` /
`decrypt`, which take and return `bytes`.

Each cipher subclasses it, declares its block size, and implements three methods:

```python
class MyCipher(EncryptionBase):
    block_size = 16                       # bytes; one block

    def generate_keys(self, key):         # key schedule
        ...
    def encrypt_block(self, plaintext):   # exactly one block -> bytes
        ...
    def decrypt_block(self, ciphertext):  # exactly one block -> bytes
        ...
```

Internals follow the specifications rather than optimized tricks:

- **AES** — GF(2^8) arithmetic (`xtime`, `gmul`), SubBytes/ShiftRows/MixColumns,
  key expansion.
- **DES** — integer-based bit permutations and expansion with a Feistel `f`
  function; `TripleDES` wraps three DES layers in EDE order.
- **Blowfish** — the full on-spec P-array and S-box tables, 16-round Feistel.
- **Twofish** — GF polynomial multiplication, MDS matrices, PHT and q-boxes.
- **Serpent** — bit-reversed words, bit-sliced S-box boolean circuits and the
  linear transform.

## API contract

Keys, plaintext, ciphertext and IVs are all `bytes`. A `str` — including a hex
string — raises `TypeError`, so there is no ambiguity about encoding.
`encrypt` / `decrypt` handle arbitrary-length data; `encrypt_block` /
`decrypt_block` take and return exactly one block.

Lengths are checked strictly and never silently adjusted; a wrong length raises
`ValueError`:

- **Keys** — AES, Twofish and Serpent: exactly 16, 24 or 32 bytes (Serpent
  applies the specification's `0x01` padding to 16- and 24-byte keys
  internally). DES: 8. 3DES: 24. Blowfish: 4–56.
- **Blocks** — exactly one block per `encrypt_block` / `decrypt_block` call.
- **IVs** — every mode except ECB needs an IV of exactly one block (for CTR,
  the initial counter block). ECB rejects an IV. There is no default IV.

## Modes and padding

- **Modes:** ECB, CBC, PCBC, CFB, OFB, CTR.
- **ECB, CBC and PCBC** operate on whole blocks, so the message is always padded
  — even block-aligned input receives a full extra block, which makes unpadding
  unambiguous. Schemes: `PKCS`, `ANSI X9.23`, `ISO 7816-4` (`bit`), `TBC`, and
  `0`/`byt` zero padding (fills to the block boundary only, so it cannot be
  removed again). `padding=""` means no padding and requires block-aligned
  input.
- **CFB, OFB and CTR** are keystream modes: no padding, and the ciphertext is
  exactly as long as the plaintext.
- Malformed padding, or a ciphertext that is not block-aligned, raises
  `ValueError`.

## Testing and verification

The test suite uses `unittest`, so it runs with the standard library alone:

```bash
python3 -m unittest discover -s tests -t tests   # everything
python3 -m unittest tests.test_aes -v             # one module
```

| Module | Covers |
|---|---|
| `tests/test_aes.py` | FIPS-197 C.1–C.3, SP 800-38A ECB and CBC |
| `tests/test_des.py` | classic DES vectors, IP/FP and `f` cross-checks, 3DES EDE properties |
| `tests/test_blowfish.py` | Schneier's official ECB and `set_key` sets |
| `tests/test_twofish.py` | the official submission KATs |
| `tests/test_serpent.py` | the NESSIE/verified sets, plus S-box cross-checks |
| `tests/test_encryption_base.py` | padding schemes and shared helpers |
| `tests/test_modes.py` | all six modes, padding and length validation |
| `tests/vectors.py` | the vector data itself, shared with `examples/verify_vectors.py` |

### Cross-implementation harness

`examples/verify_vectors.py` runs the in-repo ciphers against the official
vectors, then additionally cross-checks them against any of the following
external libraries found on the machine:

| Library      | Ciphers checked       | Loaded as          |
|--------------|-----------------------|--------------------|
| pycrypto     | AES, DES, Blowfish    | `Crypto.Cipher`    |
| libtomcrypt  | Twofish               | `libtomcrypt.so.1` |
| GNU nettle   | Serpent               | `libnettle.so.8`   |

Libraries that are not installed are reported as `SKIP`, and the exit code is
non-zero only when a vector actually fails. Triple DES is absent by design: it
has no vector of confirmed provenance here, so `tests/test_des.py` checks it
structurally instead (EDE layer order, key-split assignment, and the collapse to
single DES when all three keys match). Every other cipher and every vector is
traceable to a publication.

```bash
python3 -m examples.verify_vectors
python3 -m examples.benchmark
```

Both are run as modules (`python3 -m ...`) from the repository root, so the
repository root ends up on `sys.path` and the `src` and `tests` imports resolve.

On a machine with all three libraries installed, the harness prints:

```text
== AES ==
  in-repo  : 3/3 passed
  pycrypto   : 3/3 passed

== DES ==
  in-repo  : 3/3 passed
  pycrypto   : 3/3 passed

== Blowfish ==
  in-repo  : 55/55 passed
  pycrypto   : 55/55 passed

== Twofish ==
  in-repo  : 5/5 passed
  libtomcrypt: 5/5 passed

== Serpent ==
  in-repo  : 16/16 passed
  nettle     : 16/16 passed

ALL VECTORS PASSED for in-repo ciphers and all detected oracles
```

### Benchmark

`examples/benchmark.py` times every cipher three ways: key setup, the raw
`encrypt_block`/`decrypt_block` cost, and every mode in both directions. Where
an external library is installed it is timed too, putting a number on what the
pure-Python implementations cost. Each figure is the best of `--rounds` runs
after a warm-up, measured with `time.perf_counter()` over the bytes the call
actually processed (so the padded modes are not flattered).

```bash
python3 -m examples.benchmark                       # everything, 4000 bytes
python3 -m examples.benchmark --bytes 65536         # bigger message
python3 -m examples.benchmark --rounds 9            # steadier figures
python3 -m examples.benchmark --cipher AES --mode CBC --mode CTR
python3 -m examples.benchmark --no-native           # skip the C libraries
python3 -m examples.benchmark --json                # machine-readable
```

A trimmed run (best of 9, 4096-byte message) looks like this — the numbers are
from one machine and one run: see the caveats below.

```text
Block cipher throughput: 4096 bytes, best of 9 run(s), Python 3.14.7 on Linux
Pure-Python implementations, KB/s

cipher     block  key    key setup   raw enc   raw dec
------------------------------------------------------
DES            8    8       9115/s      71.3      65.8
TripleDES      8   24       2603/s      22.6      22.5
Blowfish       8   16        192/s     681.3     716.5
AES           16   16      40130/s      57.3      30.3
Serpent       16   32      10022/s     126.2     126.7
Twofish       16   32        130/s     268.2     291.1

Native libraries, ECB only, KB/s
  'bulk' = one native call for the whole message; 'block' = one FFI call per block (overhead-dominated)

  (DES, TripleDES, Serpent and Twofish rows omitted)

  AES        pycryptodome  [bulk] enc   268092.3   dec   286730.4
             this repo     [pure-Python] enc       67.1   dec       30.1   -> native is 3993.3x the encrypt rate
  Blowfish   pycryptodome  [bulk] enc   140818.0   dec   147525.1
             this repo     [pure-Python] enc      901.6   dec      844.7   -> native is 156.2x the encrypt rate
```

Two results are worth noting because they are counter-intuitive. **Blowfish is
the fastest cipher here, roughly 13x AES**, because it works on 64-bit blocks
and its rounds are table lookups, whereas AES spends its rounds in GF(2^8)
multiplication. And the native figures are labelled `bulk` or `block`:
pycryptodome is handed the whole message in one call, while nettle and
libtomcrypt only expose single-block ECB entry points, so those rows are
dominated by ctypes call overhead and are not a like-for-like comparison.
Absolute numbers are machine- and build-specific; only the ordering within one
run is meaningful.

## Project layout

```
pyproject.toml         Packaging metadata (src layout, no runtime deps)
src/
  __init__.py          Re-exports every cipher class
  encryption_base.py   Shared base class: XOR/permutation/rotation, mode-aware padding, all block modes
  AES.py               AES implementation
  DES.py               DES and 3DES implementations
  Blowfish.py          Blowfish implementation (includes spec tables)
  Twofish.py           Twofish implementation
  Serpent.py           Serpent implementation

tests/
  vectors.py           Published known-answer vectors, shared with examples/verify_vectors.py
  test_aes.py          FIPS-197 and SP 800-38A
  test_des.py          DES vectors, permutation cross-checks, 3DES EDE properties
  test_blowfish.py     Schneier's official ECB and set_key sets
  test_twofish.py      Official submission KATs
  test_serpent.py      NESSIE/verified sets, S-box cross-checks
  test_encryption_base.py  Padding schemes and shared helpers
  test_modes.py        All block modes, padding and length validation

examples/
  verify_vectors.py    In-repo + external-oracle verification harness
  benchmark.py         Timing script: all ciphers, all modes, both directions,
                       plus any installed native library for comparison

pylintrc             Lint configuration for the teaching-style code
```

## Requirements

- Python 3.10+
- No third-party packages are required to use the ciphers or run the built-in
  tests.
- Optional: `pip install -e ".[oracle]"` pulls in pycryptodome; alongside a
  system libtomcrypt and GNU nettle it enables the independent oracle checks in
  `examples/verify_vectors.py`.
- Optional: `pip install -e ".[dev]"` installs the lint, format and type-check
  tools — see [Development](#development).

## Development

The ciphers and tests need nothing beyond the standard library, but the quality
gates below do. Install them once as the optional `dev` extra:

```bash
pip install -e ".[dev]"     # black, mypy, pylint
pip install -e ".[oracle]"  # pycryptodome, for the external oracle checks
```

Then the repository checks itself with:

```bash
black --check src tests examples   # formatting
mypy                               # types (configuration in pyproject.toml)
pylint src tests examples          # lint (configuration in pylintrc)
```

## Security notice

This is an educational, from-scratch implementation. It implements classic
block modes (ECB/CBC/PCBC/CFB/OFB/CTR), has no key derivation, no authenticated
encryption (no MAC/AEAD), and makes no constant-time claims. Do not use it to
protect real secrets — use a vetted library such as `cryptography` instead.

## License

MIT — see [LICENSE](LICENSE).