"""Serpent (Anderson, Biham and Knudsen 1998), implemented step by step for teaching."""

from encryption_base import EncryptionBase

# The Serpent S-box tables (SBOXES) are in the appendix at the end of this file.

# Golden-ratio constant used by the key schedule (Serpent proposal,
# Section 3.2). This implementation uses a non-standard value that
# matches the C++ reference implementation in this repo (which uses
# bit-reversed byte ordering). The standard value is 0x9E3779B9.
PHI = 2644438137


class Serpent(EncryptionBase):
    """Serpent cipher; 128-bit blocks and keys, 32 rounds."""

    def __init__(self):
        self.subkeys = []

    @staticmethod
    def _bitrev8(v):
        """Reverse bits in an 8-bit value (matches C++ ltb)."""
        r = 0
        for _ in range(8):
            r = (r << 1) | (v & 1)
            v >>= 1
        return r

    @staticmethod
    def _hex_to_words_bitrev(s):
        """Convert hex string to list of 32-bit words with bit-reversal per byte.
        Matches C++ ltb() on 8-char chunks."""
        out = []
        for i in range(0, len(s), 8):
            chunk = s[i : i + 8]
            if len(chunk) < 8:
                chunk = chunk.ljust(8, "0")
            w = 0
            for j in range(0, 8, 2):
                byte = int(chunk[j : j + 2], 16)
                w = (w << 8) | Serpent._bitrev8(byte)
            out.append(w)
        return out

    @staticmethod
    def _words_to_hex_bitrev(words):
        """Convert list of 32-bit words to hex string with bit-reversal per byte."""
        out = []
        for w in words:
            for shift in (24, 16, 8, 0):
                byte = (w >> shift) & 0xFF
                out.append(f"{Serpent._bitrev8(byte):02x}")
        return "".join(out)

    def apply_sbox_bit(self, x, n, d=0):
        """Bit-sliced S-box: apply S-box n to four 32-bit bit-planes."""
        xn = [0, 0, 0, 0]
        for bit in range(32):
            newbits = SBOXES[d][n][
                ((x[0] >> bit) % 2) << 0
                | ((x[1] >> bit) % 2) << 1
                | ((x[2] >> bit) % 2) << 2
                | ((x[3] >> bit) % 2) << 3
            ]
            xn[0] |= ((newbits >> 0) % 2) << bit
            xn[1] |= ((newbits >> 1) % 2) << bit
            xn[2] |= ((newbits >> 2) % 2) << bit
            xn[3] |= ((newbits >> 3) % 2) << bit
        return xn

    def apply_sbox(self, x, n, d=0):
        """Word-sliced S-box: the hardcoded gate networks for the eight S-boxes."""
        r0, r1, r2, r3 = x
        if d == 0:
            if n == 0:
                r3 ^= r0
                r4 = r1
                r1 &= r3
                r4 ^= r2
                r1 ^= r0
                r0 |= r3
                r0 ^= r4
                r4 ^= r3
                r3 ^= r2
                r2 |= r1
                r2 ^= r4
                r4 ^= 0xFFFFFFFF
                r4 |= r1
                r1 ^= r3
                r1 ^= r4
                r3 |= r0
                r1 ^= r3
                r4 ^= r3
                return [r1, r4, r2, r0]

            if n == 1:
                r0 ^= 0xFFFFFFFF
                r2 ^= 0xFFFFFFFF
                r4 = r0
                r0 &= r1
                r2 ^= r0
                r0 |= r3
                r3 ^= r2
                r1 ^= r0
                r0 ^= r4
                r4 |= r1
                r1 ^= r3
                r2 |= r0
                r2 &= r4
                r0 ^= r1
                r1 &= r2
                r1 ^= r0
                r0 &= r2
                r0 ^= r4
                return [r2, r0, r3, r1]

            if n == 2:
                r4 = r0
                r0 &= r2
                r0 ^= r3
                r2 ^= r1
                r2 ^= r0
                r3 |= r4
                r3 ^= r1
                r4 ^= r2
                r1 = r3
                r3 |= r4
                r3 ^= r0
                r0 &= r1
                r4 ^= r0
                r1 ^= r3
                r1 ^= r4
                r4 ^= 0xFFFFFFFF
                return [r2, r3, r1, r4]

            if n == 3:
                r4 = r0
                r0 |= r3
                r3 ^= r1
                r1 &= r4
                r4 ^= r2
                r2 ^= r3
                r3 &= r0
                r4 |= r1
                r3 ^= r4
                r0 ^= r1
                r4 &= r0
                r1 ^= r3
                r4 ^= r2
                r1 |= r0
                r1 ^= r2
                r0 ^= r3
                r2 = r1
                r1 |= r3
                r1 ^= r0
                return [r1, r2, r3, r4]

            if n == 4:
                r1 ^= r3
                r3 ^= 0xFFFFFFFF
                r2 ^= r3
                r3 ^= r0
                r4 = r1
                r1 &= r3
                r1 ^= r2
                r4 ^= r3
                r0 ^= r4
                r2 &= r4
                r2 ^= r0
                r0 &= r1
                r3 ^= r0
                r4 |= r1
                r4 ^= r0
                r0 |= r3
                r0 ^= r2
                r2 &= r3
                r0 ^= 0xFFFFFFFF
                r4 ^= r2
                return [r1, r4, r0, r3]

            if n == 5:
                r0 ^= r1
                r1 ^= r3
                r3 ^= 0xFFFFFFFF
                r4 = r1
                r1 &= r0
                r2 ^= r3
                r1 ^= r2
                r2 |= r4
                r4 ^= r3
                r3 &= r1
                r3 ^= r0
                r4 ^= r1
                r4 ^= r2
                r2 ^= r0
                r0 &= r3
                r2 ^= 0xFFFFFFFF
                r0 ^= r4
                r4 |= r3
                r2 ^= r4
                return [r1, r3, r0, r2]

            if n == 6:
                r2 ^= 0xFFFFFFFF
                r4 = r3
                r3 &= r0
                r0 ^= r4
                r3 ^= r2
                r2 |= r4
                r1 ^= r3
                r2 ^= r0
                r0 |= r1
                r2 ^= r1
                r4 ^= r0
                r0 |= r3
                r0 ^= r2
                r4 ^= r3
                r4 ^= r0
                r3 ^= 0xFFFFFFFF
                r2 &= r4
                r2 ^= r3
                return [r0, r1, r4, r2]

            if n == 7:
                r4 = r1
                r1 |= r2
                r1 ^= r3
                r4 ^= r2
                r2 ^= r1
                r3 |= r4
                r3 &= r0
                r4 ^= r2
                r3 ^= r1
                r1 |= r4
                r1 ^= r0
                r0 |= r4
                r0 ^= r2
                r1 ^= r4
                r2 ^= r1
                r1 &= r0
                r1 ^= r4
                r2 ^= 0xFFFFFFFF
                r2 |= r0
                r4 ^= r2
                return [r4, r3, r1, r0]
        if n == 0:
            r2 ^= 0xFFFFFFFF
            r4 = r1
            r1 |= r0
            r4 ^= 0xFFFFFFFF
            r1 ^= r2
            r2 |= r4
            r1 ^= r3
            r0 ^= r4
            r2 ^= r0
            r0 &= r3
            r4 ^= r0
            r0 |= r1
            r0 ^= r2
            r3 ^= r4
            r2 ^= r1
            r3 ^= r0
            r3 ^= r1
            r2 &= r3
            r4 ^= r2
            return [r0, r4, r1, r3]
        if n == 1:
            r4 = r1
            r1 ^= r3
            r3 &= r1
            r4 ^= r2
            r3 ^= r0
            r0 |= r1
            r2 ^= r3
            r0 ^= r4
            r0 |= r2
            r1 ^= r3
            r0 ^= r1
            r1 |= r3
            r1 ^= r0
            r4 ^= 0xFFFFFFFF
            r4 ^= r1
            r1 |= r0
            r1 ^= r0
            r1 |= r4
            r3 ^= r1
            return [r4, r0, r3, r2]

        if n == 2:
            r2 ^= r3
            r3 ^= r0
            r4 = r3
            r3 &= r2
            r3 ^= r1
            r1 |= r2
            r1 ^= r4
            r4 &= r3
            r2 ^= r3
            r4 &= r0
            r4 ^= r2
            r2 &= r1
            r2 |= r0
            r3 ^= 0xFFFFFFFF
            r2 ^= r3
            r0 ^= r3
            r0 &= r1
            r3 ^= r4
            r3 ^= r0
            return [r1, r4, r2, r3]

        if n == 3:
            r4 = r2
            r2 ^= r1
            r0 ^= r2
            r4 &= r2
            r4 ^= r0
            r0 &= r1
            r1 ^= r3
            r3 |= r4
            r2 ^= r3
            r0 ^= r3
            r1 ^= r4
            r3 &= r2
            r3 ^= r1
            r1 ^= r0
            r1 |= r2
            r0 ^= r3
            r1 ^= r4
            r0 ^= r1
            return [r2, r1, r3, r0]
        if n == 4:
            r4 = r2
            r2 &= r3
            r2 ^= r1
            r1 |= r3
            r1 &= r0
            r4 ^= r2
            r4 ^= r1
            r1 &= r2
            r0 ^= 0xFFFFFFFF
            r3 ^= r4
            r1 ^= r3
            r3 &= r0
            r3 ^= r2
            r0 ^= r1
            r2 &= r0
            r3 ^= r0
            r2 ^= r4
            r2 |= r3
            r3 ^= r0
            r2 ^= r1
            return [r0, r3, r2, r4]
        if n == 5:
            r1 ^= 0xFFFFFFFF
            r4 = r3
            r2 ^= r1
            r3 |= r0
            r3 ^= r2
            r2 |= r1
            r2 &= r0
            r4 ^= r3
            r2 ^= r4
            r4 |= r0
            r4 ^= r1
            r1 &= r2
            r1 ^= r3
            r4 ^= r2
            r3 &= r4
            r4 ^= r1
            r3 ^= r4
            r4 ^= 0xFFFFFFFF
            r3 ^= r0
            return [r1, r4, r3, r2]
        if n == 6:
            r0 ^= r2
            r4 = r2
            r2 &= r0
            r4 ^= r3
            r2 ^= 0xFFFFFFFF
            r3 ^= r1
            r2 ^= r3
            r4 |= r0
            r0 ^= r2
            r3 ^= r4
            r4 ^= r1
            r1 &= r3
            r1 ^= r0
            r0 ^= r3
            r0 |= r2
            r3 ^= r1
            r4 ^= r0
            return [r1, r2, r4, r3]
        if n == 7:
            r4 = r2
            r2 ^= r0
            r0 &= r3
            r4 |= r3
            r2 ^= 0xFFFFFFFF
            r3 ^= r1
            r1 |= r0
            r0 ^= r2
            r2 &= r4
            r3 &= r4
            r1 ^= r2
            r2 ^= r0
            r0 |= r2
            r4 ^= r1
            r0 ^= r3
            r3 ^= r4
            r4 |= r0
            r3 ^= r2
            r4 ^= r2
            return [r3, r0, r1, r4]
        return x

    def generate_keys(self, key):
        """Expand the 128-bit hex key into 33 round subkeys."""
        # The spec pads short keys by appending a '1' bit, i.e. a byte of
        # 0x01 immediately after the key bytes, then zeros to 256 bits.
        # Expand to 32 bytes.
        target = 32
        if len(key) % 2:
            key += "0"
        n = len(key) // 2
        if n > target:
            key = key[: 2 * target]
        elif n < target:
            key = key[: 2 * n] + "01" + "00" * (target - n - 1)
        w = self._hex_to_words_bitrev(key)
        for i in range(8, 140):
            wi = w[i - 8] ^ w[i - 5] ^ w[i - 3] ^ w[i - 1] ^ PHI ^ self._bitrev32(i - 8)
            wi = self.rotl(wi, 11, 32)
            w.append(wi)
        sk1 = []
        for i in range(33):
            k = self.apply_sbox(
                [w[4 * i + 8], w[4 * i + 1 + 8], w[4 * i + 2 + 8], w[4 * i + 3 + 8]],
                (((32 + 3 - i) % 32) % 8),
            )
            sk1.append(k)
        self.subkeys = sk1

    @staticmethod
    def _bitrev32(v):
        """Reverse bits in a 32-bit value (matches C++ ltb32)."""
        r = 0
        for _ in range(32):
            r = (r << 1) | (v & 1)
            v >>= 1
        return r

    def lt(self, x):
        """Linear Transformation (diffusion) applied between rounds."""
        x[0] = self.rotl(x[0], 13, 32)
        x[2] = self.rotl(x[2], 3, 32)
        x[1] = x[1] ^ x[0] ^ x[2]
        x[3] = x[3] ^ x[2] ^ (x[0] >> 3)
        x[1] = self.rotl(x[1], 1, 32)
        x[3] = self.rotl(x[3], 7, 32)
        x[0] = x[0] ^ x[1] ^ x[3]
        x[2] = x[2] ^ x[3] ^ (x[1] >> 7)
        x[0] = self.rotl(x[0], 5, 32)
        x[2] = self.rotl(x[2], 22, 32)
        return x

    def lt_inverse(self, x):
        """Inverse Linear Transformation, used by decryption."""
        x[2] = self.rotr(x[2], 22, 32)
        x[0] = self.rotr(x[0], 5, 32)
        x[2] = x[2] ^ x[3] ^ (x[1] >> 7)
        x[0] = x[0] ^ x[1] ^ x[3]
        x[3] = self.rotr(x[3], 7, 32)
        x[1] = self.rotr(x[1], 1, 32)
        x[3] = x[3] ^ x[2] ^ (x[0] >> 3)
        x[1] = x[1] ^ x[0] ^ x[2]
        x[2] = self.rotr(x[2], 3, 32)
        x[0] = self.rotr(x[0], 13, 32)
        return x

    def get_block_size(self):
        """Serpent uses a 128-bit (16-byte) block size."""
        return 16

    def encrypt_block(self, plaintext: bytes) -> bytes:
        """Encrypt one 128-bit block given as bytes."""
        x = self._hex_to_words_bitrev(plaintext.hex())
        for r in range(32):
            x = [x[i] ^ self.subkeys[r][i] for i in range(4)]
            x = self.apply_sbox(x, r % 8)
            if r == 31:
                break
            x = self.lt(x)
        x = [x[i] ^ self.subkeys[32][i] for i in range(4)]
        return bytes.fromhex(self._words_to_hex_bitrev(x))

    def decrypt_block(self, ciphertext: bytes) -> bytes:
        """Decrypt one 128-bit block given as bytes."""
        x = self._hex_to_words_bitrev(ciphertext.hex())
        x = [x[i] ^ self.subkeys[32][i] for i in range(4)]
        x = self.apply_sbox(x, 31 % 8, d=1)
        x = [x[i] ^ self.subkeys[31][i] for i in range(4)]
        for r in range(30, -1, -1):
            x = self.lt_inverse(x)
            x = self.apply_sbox(x, r % 8, d=1)
            x = [x[i] ^ self.subkeys[r][i] for i in range(4)]
        return bytes.fromhex(self._words_to_hex_bitrev(x))

#
# ---- Serpent data tables (appendix) ----
#

# Serpent S-boxes (Anderson, Biham & Knudsen, "Serpent: A Proposal for the
# Advanced Encryption Standard", Appendix A). Index 0 holds the eight forward
# S-boxes, index 1 the inverse ones; round n uses S-box n mod 8.
# Consumed by apply_sbox_bit().
SBOXES = [
    [
        [3, 8, 15, 1, 10, 6, 5, 11, 14, 13, 4, 2, 7, 0, 9, 12],
        [15, 12, 2, 7, 9, 0, 5, 10, 1, 11, 14, 8, 6, 13, 3, 4],
        [8, 6, 7, 9, 3, 12, 10, 15, 13, 1, 14, 4, 0, 11, 5, 2],
        [0, 15, 11, 8, 12, 9, 6, 3, 13, 1, 2, 4, 10, 7, 5, 14],
        [1, 15, 8, 3, 12, 0, 11, 6, 2, 5, 4, 10, 9, 14, 7, 13],
        [15, 5, 2, 11, 4, 10, 9, 12, 0, 3, 14, 8, 13, 6, 7, 1],
        [7, 2, 12, 5, 8, 4, 6, 11, 14, 9, 1, 15, 13, 3, 10, 0],
        [1, 13, 15, 0, 14, 8, 2, 11, 7, 4, 12, 10, 9, 3, 5, 6],
    ],
    [
        [13, 3, 11, 0, 10, 6, 5, 12, 1, 14, 4, 7, 15, 9, 8, 2],
        [5, 8, 2, 14, 15, 6, 12, 3, 11, 4, 7, 9, 1, 13, 10, 0],
        [12, 9, 15, 4, 11, 14, 1, 2, 0, 3, 6, 13, 5, 8, 10, 7],
        [0, 9, 10, 7, 11, 14, 6, 13, 3, 5, 12, 2, 4, 8, 15, 1],
        [5, 0, 8, 3, 10, 9, 7, 14, 2, 12, 11, 6, 4, 15, 13, 1],
        [8, 15, 2, 9, 4, 1, 13, 14, 11, 6, 5, 3, 7, 12, 10, 0],
        [15, 10, 1, 13, 5, 3, 6, 0, 4, 9, 14, 7, 2, 12, 8, 11],
        [3, 0, 6, 13, 9, 14, 15, 8, 5, 12, 11, 7, 10, 1, 4, 2],
    ],
]
