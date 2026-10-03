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
`encryption_base.py`. It provides the common building blocks (XOR, bit
permutations, rotations, padding) and the block-mode `encrypt` / `decrypt`,
which take and return `bytes`.

Each cipher subclasses it, declares its block size, and implements three methods:

```python
block_size = 16                   # class attribute, bytes
generate_keys(key)               # key schedule (bytes)
encrypt_block(plaintext)  -> bytes
decrypt_block(ciphertext) -> bytes
```

Internals follow the specifications rather than optimized tricks:

- **AES** – GF(2^8) arithmetic (`xtime`, `gmul`), SubBytes/ShiftRows/MixColumns, key expansion.
- **DES** – integer-based bit permutations/expansion and a Feistel `f` function; `TripleDES` is EDE.
- **Blowfish** – full on-spec P-array and S-box tables, 16-round Feistel.
- **Twofish** – GF polynomial multiplication, MDS matrices, PHT, q-boxes.
- **Serpent** – bit-reversed words, bit-sliced S-box boolean circuits, linear transform.

## Usage

```python
from AES import AES

c = AES()
c.generate_keys(bytes.fromhex("000102030405060708090a0b0c0d0e0f"))
c.encrypt_block(bytes.fromhex("00112233445566778899aabbccddeeff")).hex()
# '69c4e0d86a7b0430d8cdb78070b4c55a'
```

Keys, plaintext, ciphertext and IVs are all `bytes` (a `str`, including a hex
string, raises `TypeError`). `encrypt` / `decrypt` handle arbitrary-length data.
Default mode is CBC with ISO 7816-4 padding.

```python
import os

iv = os.urandom(16)   # fresh, unpredictable, one block long
ct = c.encrypt(b"attack at dawn", mode="CBC", padding="ISO 7816-4", iv=iv)
pt = c.decrypt(ct, mode="CBC", padding="ISO 7816-4", iv=iv)
# b'attack at dawn'
```

Lengths are checked strictly and never silently adjusted; a wrong length raises
`ValueError`:

- **Keys:** AES, Twofish and Serpent take exactly 16, 24 or 32 bytes (Serpent
  applies the spec's `0x01` padding to 16/24-byte keys internally), DES 8,
  3DES 24, Blowfish 4–56.
- **Blocks:** `encrypt_block` / `decrypt_block` take exactly one block.
- **IVs:** every mode except ECB needs an IV of exactly one block (for CTR, the
  initial counter block). ECB rejects an IV. There is no default IV.

## Modes and padding

- Modes: **ECB, CBC, PCBC, CFB, OFB, CTR**.
- Padding depends on the mode:
  - **ECB, CBC, PCBC** work on whole blocks, so the message is always padded,
    including block-aligned input (a full extra block is added). This makes
    unpadding unambiguous. Schemes: `PKCS`, `ANSI X9.23`, `ISO 7816-4` (`bit`),
    `TBC`, and `0`/`byt` zero padding (fills to the block boundary only, so it
    cannot be removed again). `padding=""` means no padding and requires
    block-aligned input.
  - **CFB, OFB, CTR** are keystream modes: no padding, and the ciphertext has
    exactly the length of the plaintext.
  - Malformed padding or a ciphertext that is not block-aligned raises
    `ValueError`.
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
python3 ModeTest.py       #   all block modes across every cipher
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

- Python 3.10+
- No third-party packages required to use the ciphers or run the built-in tests.
- Optional: pycrypto (or pycryptodome), libtomcrypt, and GNU nettle to enable
  the independent oracle checks in `verify_vectors.py`.

## Project layout

```
encryption_base.py   Shared base class: XOR/permutation/rotation, mode-aware padding, all block modes
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
ModeTest.py          Block-mode round trips (ECB/CBC/PCBC/CFB/OFB/CTR)
verify_vectors.py    In-repo + external-oracle verification harness
benchmark.py         Timing script for the ciphers
pylintrc             Lint configuration for the teaching-style code
```

## Security notice

This is an educational, from-scratch implementation. It implements classic
block modes (ECB/CBC/PCBC/CFB/OFB/CTR), has no key derivation, no
authenticated encryption (no MAC/AEAD), and makes no constant-time claims.
Do not use it to protect real secrets — use a vetted library such as
`cryptography` instead.

## License

MIT — see [LICENSE](LICENSE).
