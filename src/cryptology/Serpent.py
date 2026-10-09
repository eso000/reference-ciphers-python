"""Serpent (Anderson, Biham and Knudsen 1998), implemented step by step for teaching."""

from .encryption_base import EncryptionBase

# The Serpent S-box tables (SBOXES) are in the appendix at the end of this file.

# Fractional part of the golden ratio, 2^32 * ((sqrt(5) - 1) / 2), mixed into
# the prekey recurrence of the key schedule (Serpent proposal, Section 4).
PHI = 0x9E3779B9


class Serpent(EncryptionBase):
    """Serpent cipher; 128-bit blocks and keys, 32 rounds.

    The rounds follow the bitslice description of the Serpent proposal: the
    cipher (Section 3) and the key schedule (Section 4). A block is held as
    four 32-bit words in little-endian bit order, so the paper's ``<<<`` and
    ``<<`` are plain :meth:`rotl` and masked left shifts on those words.
    Python integers do not wrap, hence the ``& 0xFFFFFFFF`` after each shift.

    ``use_alt`` selects the S-box implementation: ``True`` (default) uses the
    word-sliced gate networks in apply_sbox (fast), ``False`` uses the
    bit-sliced table path apply_sbox_bit driven by the SBOXES appendix. Both
    produce identical ciphertext.
    """

    block_size = 16  # 128 bits = 16 bytes

    def __init__(self, use_alt: bool = True):
        self.subkeys: list[list[int]] = []
        self.use_alt = use_alt

    def _sbox(self, x, n, d=0):
        """Dispatch to the selected S-box implementation."""
        return (
            self.apply_sbox(x, n, d) if self.use_alt else self.apply_sbox_bit(x, n, d)
        )

    @staticmethod
    def _bytes_to_words(data: bytes):
        """Split bytes into 32-bit words, 4 bytes per word, little-endian.

        That is Serpent's bit order: the first bit of the block ends up as the
        least significant bit of word 0 (Serpent proposal, Section 3.3)."""
        return [
            int.from_bytes(data[i : i + 4], "little") for i in range(0, len(data), 4)
        ]

    @staticmethod
    def _words_to_bytes(words) -> bytes:
        """Pack 32-bit words back into bytes, 4 bytes per word, little-endian."""
        return b"".join(w.to_bytes(4, "little") for w in words)

    def apply_sbox_bit(self, x, n, d=0):
        """Bit-sliced S-box: apply S-box n to four 32-bit bit-planes.

        Bit k of each word is one of the 32 parallel copies of the 4-bit S-box
        that the paper runs on a single block (Section 2.1)."""
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

    def generate_keys(self, key: bytes) -> None:
        """Expand a 16, 24 or 32 byte key into 33 round subkeys."""
        # The spec pads keys shorter than 256 bits by appending a '1' bit, i.e.
        # a byte of 0x01 immediately after the key bytes, then zeros to 256 bits.
        key = self._checked_key(key, (16, 24, 32), "Serpent")
        target = 32
        if len(key) < target:
            key = key + b"\x01" + b"\x00" * (target - len(key) - 1)
        # Prekey recurrence (Section 4):
        #     w_i := (w_i-8 ^ w_i-5 ^ w_i-3 ^ w_i-1 ^ PHI ^ i) <<< 11
        # where the eight key words are w_-8 .. w_-1, so w[8:] holds w_0 .. w_131.
        w = self._bytes_to_words(key)
        for i in range(8, 140):
            wi = w[i - 8] ^ w[i - 5] ^ w[i - 3] ^ w[i - 1] ^ PHI ^ (i - 8)
            wi = self.rotl(wi, 11, 32)
            w.append(wi)
        # Subkey i is prekeys 4i .. 4i+3 run through S-box (3 - i) mod 8, which
        # is the S3, S2, S1, S0, S7, S6, S5, S4 order listed in Section 4.
        sk1 = []
        for i in range(33):
            k = self._sbox(
                [w[4 * i + 8], w[4 * i + 1 + 8], w[4 * i + 2 + 8], w[4 * i + 3 + 8]],
                (3 - i) % 8,
            )
            sk1.append(k)
        self.subkeys = sk1

    def lt(self, x):
        """Linear Transformation (diffusion) applied between rounds.

        A transcription of the paper's listing (Section 3):

            X0 := X0 <<< 13
            X2 := X2 <<< 3
            X1 := X1 ^ X0 ^ X2
            X3 := X3 ^ X2 ^ (X0 << 3)
            X1 := X1 <<< 1
            X3 := X3 <<< 7
            X0 := X0 ^ X1 ^ X3
            X2 := X2 ^ X3 ^ (X1 << 7)
            X0 := X0 <<< 5
            X2 := X2 <<< 22
        """
        x[0] = self.rotl(x[0], 13, 32)
        x[2] = self.rotl(x[2], 3, 32)
        x[1] = x[1] ^ x[0] ^ x[2]
        x[3] = x[3] ^ x[2] ^ ((x[0] << 3) & 0xFFFFFFFF)
        x[1] = self.rotl(x[1], 1, 32)
        x[3] = self.rotl(x[3], 7, 32)
        x[0] = x[0] ^ x[1] ^ x[3]
        x[2] = x[2] ^ x[3] ^ ((x[1] << 7) & 0xFFFFFFFF)
        x[0] = self.rotl(x[0], 5, 32)
        x[2] = self.rotl(x[2], 22, 32)
        return x

    def lt_inverse(self, x):
        """Inverse Linear Transformation, used by decryption.

        The same ten steps as lt in reverse order, with every rotation turned
        around, which is the paper's inverse transformation."""
        x[2] = self.rotr(x[2], 22, 32)
        x[0] = self.rotr(x[0], 5, 32)
        x[2] = x[2] ^ x[3] ^ ((x[1] << 7) & 0xFFFFFFFF)
        x[0] = x[0] ^ x[1] ^ x[3]
        x[3] = self.rotr(x[3], 7, 32)
        x[1] = self.rotr(x[1], 1, 32)
        x[3] = x[3] ^ x[2] ^ ((x[0] << 3) & 0xFFFFFFFF)
        x[1] = x[1] ^ x[0] ^ x[2]
        x[2] = self.rotr(x[2], 3, 32)
        x[0] = self.rotr(x[0], 13, 32)
        return x

    def encrypt_block(self, plaintext: bytes) -> bytes:
        """Encrypt one 128-bit block given as bytes."""
        x = self._bytes_to_words(self._checked_block(plaintext))
        for r in range(32):
            x = [x[i] ^ self.subkeys[r][i] for i in range(4)]
            x = self._sbox(x, r % 8)
            if r == 31:
                break
            x = self.lt(x)
        x = [x[i] ^ self.subkeys[32][i] for i in range(4)]
        return self._words_to_bytes(x)

    def decrypt_block(self, ciphertext: bytes) -> bytes:
        """Decrypt one 128-bit block given as bytes."""
        x = self._bytes_to_words(self._checked_block(ciphertext))
        x = [x[i] ^ self.subkeys[32][i] for i in range(4)]
        x = self._sbox(x, 7, d=1)  # the last round used S7
        x = [x[i] ^ self.subkeys[31][i] for i in range(4)]
        for r in range(30, -1, -1):
            x = self.lt_inverse(x)
            x = self._sbox(x, r % 8, d=1)
            x = [x[i] ^ self.subkeys[r][i] for i in range(4)]
        return self._words_to_bytes(x)


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
