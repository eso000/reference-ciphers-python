# Cryptology (Python)

From-scratch, dependency-free implementations of six classic block ciphers in
pure Python. The goal is clarity and correctness: every primitive is written
out step by step, and every cipher is checked against the official published
test vectors and, when available, against independent crypto libraries.

## Ciphers

| Cipher    | Block size | Key sizes        | Standard / source                     |
|-----------|-----------:|------------------|---------------------------------------|
| AES       | 128 bit    | 128 / 192 / 256  | FIPS-197                              |
| DES       | 64 bit     | 56 bit (+parity) | FIPS 46-3                             |
| 3DES      | 64 bit     | 168 bit (EDE)    | NIST SP 800-67                        |
| Blowfish  | 64 bit     | 32–448 bit       | Bruce Schneier, 1993                  |
| Twofish   | 128 bit    | 128 / 192 / 256  | AES submission (Schneier et al.)      |
| Serpent   | 128 bit    | 128 / 192 / 256  | NESSIE finalist (Anderson et al.)     |

## Architecture

All ciphers share one abstract base class, `EncryptionBase` in
`encryption_base.py`. It provides the common building blocks (hex/bin/bytes
conversion, XOR, bit permutations, rotations, padding) and the block-mode
drivers `encrypt_mode` / `decrypt_mode`.

Each cipher subclasses it and implements four methods:

```python
get_block_size()                 # block size in bytes
generate_keys(key)               # key schedule (hex string or bytes)
encrypt_block(plaintext)  -> bytes
decrypt_block(ciphertext) -> bytes
```

Internals follow the specifications rather than optimized tricks:

- **AES** – GF(2^8) arithmetic (`xtime`, `gmul`), SubBytes/ShiftRows/MixColumns, key expansion.
- **DES** – integer-based bit permutations/expansion and a Feistel `f` function; `TrippleDES` is EDE.
- **Blowfish** – full on-spec P-array and S-box tables, 16-round Feistel.
- **Twofish** – GF polynomial multiplication, MDS matrices, PHT, q-boxes.
- **Serpent** – bit-reversed words, bit-sliced S-box boolean circuits, linear transform.

## Usage

```python
from AES import AES

c = AES()
c.generate_keys("000102030405060708090a0b0c0d0e0f")
c.encrypt_block(bytes.fromhex("00112233445566778899aabbccddeeff")).hex()
# '69c4e0d86a7b0430d8cdb78070b4c55a'
```

Higher-level helpers encrypt arbitrary-length data. Inputs may be `bytes`
(output `bytes`) or hex strings (output hex). Defaults: CBC mode with
ISO 7816-4 padding.

```python
ct = c.encrypt("00112233445566778899aabbccddeeff", mode="CBC",
               padding="ISO 7816-4", iv="00000000000000000000000000000000")
pt = c.decrypt(ct, mode="CBC",
               padding="ISO 7816-4", iv="00000000000000000000000000000000")
```

## Modes and padding

- Modes: **ECB** and **CBC**.
- Padding: bit-level zero padding and **ISO 7816-4**, plus unpadding.
- Block-level API (`encrypt_block` / `decrypt_block`) takes exactly one block.

## Verification

Every cipher is verified against official vectors:

```bash
python3 test.py           # quick smoke test, one vector per cipher
python3 AESTest.py        # per-cipher suites:
python3 DESTest.py        #   FIPS-197 / SP 800-38A (AES), classic DES values,
python3 BlowfishTest.py   #   Schneier's Blowfish sets, Twofish KATs,
python3 TwofishTest.py    #   NESSIE Serpent set
python3 SerpentTest.py
```

`verify_vectors.py` is a cross-implementation harness. It always runs the
in-repo ciphers against the official vectors, then additionally cross-checks
them against any of these external libraries found on the machine:

| Library      | Ciphers checked              | Loaded as            |
|--------------|------------------------------|----------------------|
| pycrypto     | AES, DES, 3DES, Blowfish     | `Crypto.Cipher`      |
| libtomcrypt  | Twofish                      | `libtomcrypt.so.1`   |
| GNU nettle   | Serpent                      | `libnettle.so.8`     |

Libraries that are not installed are reported as `SKIP`; the exit code is
non-zero only when a vector actually fails.

```bash
python3 verify_vectors.py
```

## Requirements

- Python 3.9+
- No third-party packages required to use the ciphers or run the built-in tests.
- Optional: pycrypto (or pycryptodome), libtomcrypt, and GNU nettle to enable
  the independent oracle checks in `verify_vectors.py`.

## Project layout

```
encryption_base.py   Shared base class: conversions, padding, ECB/CBC modes
AES.py               AES implementation
DES.py               DES and 3DES implementations
Blowfish.py          Blowfish implementation (includes spec tables)
Twofish.py           Twofish implementation
Serpent.py           Serpent implementation

AESTest.py           AES test vectors
DESTest.py           DES / 3DES test vectors
BlowfishTest.py      Blowfish test vectors
TwofishTest.py       Twofish test vectors
SerpentTest.py       Serpent (NESSIE) test vectors

test.py              Quick end-to-end smoke test
verify_vectors.py    In-repo + external-oracle verification harness
benchmark.py         Timing script for the ciphers
pylintrc             Lint configuration for the teaching-style code
```

## Security notice

This is an educational, from-scratch implementation. It supports only ECB/CBC,
has no key derivation, no authenticated encryption (no MAC/AEAD), and makes no
constant-time claims. Do not use it to protect real secrets — use a vetted
library such as `cryptography` instead.

## License

MIT — see [LICENSE](LICENSE).
