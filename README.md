# refciphers: reference block-cipher implementations in pure Python

[![CI](https://github.com/eso000/reference-ciphers-python/actions/workflows/ci.yml/badge.svg)](https://github.com/eso000/reference-ciphers-python/actions/workflows/ci.yml)
![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue)
![License: MIT](https://img.shields.io/badge/license-MIT-green)
![Dependencies: none](https://img.shields.io/badge/dependencies-none-brightgreen)

From-scratch, dependency-free, teaching-oriented *reference implementations* of
six classic block ciphers in pure Python — written to be read. Every primitive
is spelled out step by step, and every cipher is checked against the official
published test vectors, against an independent implementation of the same math,
and, where available, against a third-party crypto library used as an oracle.

Imported as the `refciphers` package, installed as the `reference-ciphers-python`
distribution, and used from the shell through the `refciphers` command. (The
import name is deliberately not `cryptology`, which is an unrelated project on PyPI.)

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
- **A command-line front end** — `refciphers encrypt` / `decrypt` / `info`, a
  thin wrapper over the same bytes-only API.
- **Strict, predictable API** — bytes in, bytes out; wrong lengths raise
  `ValueError`, hex strings raise `TypeError`.
- **Written to be read** — internals follow the specifications rather than
  micro-optimized tricks; DES's initial/final permutation is the one credited
  exception (see [References and attribution](#references-and-attribution)).

## Ciphers

| Cipher    | Block size | Key sizes        | Standard / source                     |
|-----------|-----------:|------------------|---------------------------------------|
| AES       | 128 bit    | 128 / 192 / 256  | FIPS-197                              |
| DES       | 64 bit     | 56 bit (+parity) | FIPS 46-3                             |
| 3DES      | 64 bit     | 168 bit (EDE)    | NIST SP 800-67                        |
| Blowfish  | 64 bit     | 32–448 bit       | Bruce Schneier, 1993                  |
| Twofish   | 128 bit    | 128 / 192 / 256  | AES submission (Schneier et al.)      |
| Serpent   | 128 bit    | 128 / 192 / 256  | NESSIE finalist (Anderson et al.)     |

## Requirements

- Python 3.10+.
- No runtime dependencies (`dependencies = []`).
- To use the ciphers or run the tests from a checkout, either install once in
  editable mode (`pip install -e .`) or put `src` on `PYTHONPATH`. The package
  lives under `src/` (a proper `src` layout), so it is not importable from the
  repository root by itself.

## Quick start

```bash
pip install -e .                  # once, from the repository root
```

```python
from refciphers import AES

c = AES()
c.generate_keys(bytes.fromhex("000102030405060708090a0b0c0d0e0f"))
c.encrypt_block(bytes.fromhex("00112233445566778899aabbccddeeff")).hex()
# '69c4e0d86a7b0430d8cdb78070b4c55a'
```

Without installing (everything still works through `PYTHONPATH=src`):

```bash
PYTHONPATH=src python3 -c "from refciphers import AES; print(AES)"
```

For whole messages, `encrypt` / `decrypt` handle any length. The default mode is
CBC with ISO 7816-4 padding:

```python
import os

c = AES()
c.generate_keys(bytes.fromhex("000102030405060708090a0b0c0d0e0f"))
iv = os.urandom(16)                      # fresh, unpredictable, one block long
ct = c.encrypt(b"attack at dawn", mode="CBC", padding="ISO 7816-4", iv=iv)
pt = c.decrypt(ct, mode="CBC", padding="ISO 7816-4", iv=iv)
# b'attack at dawn'
```

## Command line

The `refciphers` command wraps the Python API, with no key derivation and no
authentication added:

```bash
refciphers info                        # supported ciphers, modes and padding
refciphers --version

refciphers encrypt --cipher aes --key 000102030405060708090a0b0c0d0e0f \
    --mode CBC --iv random -i plain.txt -o cipher.bin
refciphers decrypt --cipher aes --key 000102030405060708090a0b0c0d0e0f \
    --mode CBC --iv 19dc9fa9a4e6a1b2c3d4e5f6a7b8c9d0 -i cipher.bin -o plain.out
```

- `--iv random` (the encrypt default) generates a fresh IV and prints it to
  stderr as `iv=<hex>` so it can be stored for decryption. Decrypting requires
  an explicit `--iv`.
- Keys are given as hex with `--key`, or as raw bytes through `--key-file`.
- `-i`/`-o` default to stdin/stdout; `--format hex` reads or writes hex
  ciphertext instead of raw bytes.
- `refciphers info` lists every supported cipher with its block and key sizes.

The command is a reference/education tool — see the [Security
notice](#security-notice) at the bottom.

## Architecture

All ciphers share one base class, `EncryptionBase` in
`src/refciphers/encryption_base.py`. It provides the common building blocks
(byte-level XOR, bit permutations, rotations, padding) and the block-mode
`encrypt` / `decrypt`, which take and return `bytes`.

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

Lengths are checked strictly; a wrong length raises `ValueError`:

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

The test suite uses `unittest` and needs nothing beyond the standard library.
Run it from the repository root after the editable install:

```bash
python3 -m unittest discover -s tests -t tests   # everything
python3 -m unittest tests/test_aes.py -v         # one module, verbose
```

The suite records 107 tests. Coverage is measured with `coverage.py` and the
pure-Python package currently reports ~98% (line and branch); `pyproject.toml`
enforces a 90% floor.

| Module | Covers |
|---|---|
| `tests/test_aes.py` | FIPS-197 C.1–C.3, SP 800-38A ECB and CBC |
| `tests/test_des.py` | classic DES vectors, IP/FP and `f` cross-checks, 3DES EDE properties |
| `tests/test_blowfish.py` | Schneier's official ECB and `set_key` sets |
| `tests/test_twofish.py` | the official submission KATs |
| `tests/test_serpent.py` | the NESSIE/verified sets, plus S-box cross-checks |
| `tests/test_encryption_base.py` | padding schemes and shared helpers |
| `tests/test_modes.py` | all six modes, padding and length validation |
| `tests/test_cli.py` | the `refciphers` command: round-trips, random IV, `info`, error exits |
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
repository root ends up on `sys.path` and the `tests` package resolves; the
editable install makes `refciphers` importable.

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
pyproject.toml         Packaging metadata (src layout, no runtime deps); console script `refciphers`
src/
  refciphers/
    __init__.py        Re-exports every cipher class
    cli.py             `refciphers` command: encrypt / decrypt / info
    __main__.py        Enables `python -m refciphers`
    encryption_base.py Shared base class: XOR/permutation/rotation, mode-aware padding, all block modes
    AES.py             AES implementation
    DES.py             DES and 3DES implementations
    Blowfish.py        Blowfish implementation (includes spec tables)
    Twofish.py         Twofish implementation
    Serpent.py         Serpent implementation

tests/
  vectors.py           Published known-answer vectors, shared with examples/verify_vectors.py
  cipher_test_base.py  Shared mixins for KAT, round-trip and agreement tests
  test_aes.py          FIPS-197 and SP 800-38A
  test_des.py          DES vectors, permutation cross-checks, 3DES EDE properties
  test_blowfish.py     Schneier's official ECB and set_key sets
  test_twofish.py      Official submission KATs
  test_serpent.py      NESSIE/verified sets, S-box cross-checks
  test_encryption_base.py  Padding schemes and shared helpers
  test_modes.py        All block modes, padding and length validation
  test_cli.py          The `refciphers` command line

examples/
  verify_vectors.py    In-repo + external-oracle verification harness
  benchmark.py         Timing script: all ciphers, all modes, both directions,
                       plus any installed native library for comparison

pylintrc             Lint configuration for the teaching-style code
```

## Development

The ciphers and tests need nothing beyond the standard library, but the quality
gates below do. Install them once as the optional `dev` extra:

```bash
pip install -e ".[dev]"     # black, mypy, pylint, coverage
pip install -e ".[oracle]"  # pycryptodome, for the external oracle checks
```

Then the repository checks itself with:

```bash
black --check src tests examples   # formatting
mypy                               # types (configuration in pyproject.toml)
pylint src tests examples          # lint (configuration in pylintrc)
coverage run -m unittest discover -s tests -t tests
coverage report -m                 # fails if coverage drops below 90%
```

## References and attribution

Every cipher is implemented from a published specification, and every constant
table is taken from one. This section ties the implementations back to their
sources.

| Cipher   | Specification | Constants and tables |
|----------|---------------|----------------------|
| AES      | FIPS 197 | S-box and inverse S-box (FIPS 197 §5.1) |
| DES      | FIPS 46-3 | IP, FP, E, P, S-boxes, PC-1/PC-2 (FIPS 46-3) |
| 3DES     | SP 800-67 Rev. 2 | reuses the DES tables |
| Blowfish | Schneier (FSE 1993) | P-array and S-boxes (the hexadecimal digits of pi, *Applied Cryptography* 2nd ed., appendix A.1) |
| Twofish  | Schneier, Kelsey, Whiting, Wagner, Hall and Ferguson (AES submission, 1998) | MDS and RS matrices, q0/q1 permutations |
| Serpent  | Anderson, Biham and Knudsen (1998) | S-boxes and the bitslice gate networks (proposal §3) |

The block modes (ECB, CBC, CFB, OFB, CTR) are from SP 800-38A; PCBC is a legacy
construction (ANSI X9.52 / Kerberos). Padding schemes are PKCS#7 (RFC 2315),
ANSI X9.23, ISO/IEC 7816-4, trailing bit complement, and zero padding.

### Borrowed code

The ciphers are written from the specifications, with one exception. The DES
initial and final permutations in `src/refciphers/DES.py` use a delta-swap
bit-network — Wei Dai's variant of Richard Outerbridge's IP/FP algorithm —
instead of a per-bit table loop. The table-driven path it replaces is kept
behind `use_alt=False`, and `tests/test_des.py` checks that the two agree.

### Third-party code

pycryptodome, libtomcrypt and GNU nettle appear only in
`examples/verify_vectors.py` and `examples/benchmark.py`, as independent
oracles used to check the output of the in-repo ciphers. They are not imported
or linked by the library itself, which has no runtime dependencies.

### Further reading

- NIST, *Advanced Encryption Standard (AES)*, FIPS 197 (2001; updated 2023) — <https://csrc.nist.gov/pubs/fips/197/final>
- NIST, *Data Encryption Standard (DES)*, FIPS 46-3 (1999; withdrawn 2005) — <https://csrc.nist.gov/pubs/fips/46-3/final>
- NIST, *Recommendation for the Triple Data Encryption Algorithm (TDEA) Block Cipher*, SP 800-67 Rev. 2 (2017; withdrawn 2024) — <https://csrc.nist.gov/pubs/sp/800/67/r2/final>
- NIST, *Recommendation for Block Cipher Modes of Operation: Methods and Techniques*, SP 800-38A (2001) — <https://csrc.nist.gov/pubs/sp/800/38/a/final>
- B. Schneier, *Description of a New Variable-Length Key, 64-Bit Block Cipher (Blowfish)*, FSE 1993 — <https://www.schneier.com/academic/blowfish/>
- B. Schneier, J. Kelsey, D. Whiting, D. Wagner, C. Hall and N. Ferguson, *Twofish: A 128-Bit Block Cipher*, AES submission (1998) — <https://www.schneier.com/academic/twofish/>
- R. Anderson, E. Biham and L. Knudsen, *Serpent: A Proposal for the Advanced Encryption Standard* (1998) — <https://www.cl.cam.ac.uk/~rja14/Papers/serpent.pdf>
- B. Kaliski, *PKCS #7: Cryptographic Message Syntax Version 1.5*, RFC 2315 (1998) — <https://www.rfc-editor.org/rfc/rfc2315>

## Security notice

This is an educational, from-scratch implementation. It implements classic
block modes (ECB/CBC/PCBC/CFB/OFB/CTR), has no key derivation, no authenticated
encryption (no MAC/AEAD), and makes no constant-time claims. Do not use it to
protect real secrets — use a vetted library such as `cryptography` instead.

## License

MIT — see [LICENSE](LICENSE).