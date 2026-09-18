"""Twofish (Schneier et al., 1998), implemented step by step for teaching."""

from encryption_base import EncryptionBase

# RS matrix (Twofish, Schneier/Kelsey/Whiting/Wagner/Hall/Ferguson 1998,
# Section 3.4): maps the key bytes into the S-box vector L. Used by generate_keys.
RS = [
    [1, 164, 85, 135, 90, 88, 219, 158],
    [164, 86, 130, 243, 30, 198, 104, 229],
    [2, 161, 252, 193, 71, 174, 61, 25],
    [164, 85, 135, 90, 88, 219, 158, 3],
]

# MDS matrix (Twofish, Section 2.2.1): mixes the S-box bytes within a 32-bit
# word. Row v of the matrix lands in byte lane v. Used by mds_lt_m.
MDS = [
    [1, 239, 91, 91],
    [91, 239, 239, 1],
    [239, 91, 1, 239],
    [239, 1, 239, 91],
]

# q0/q1 permutation tables (Twofish, Appendix a.6). Used by q().
TQ = [
    [
        [8, 1, 7, 13, 6, 15, 3, 2, 0, 11, 5, 9, 14, 12, 10, 4],
        [14, 12, 11, 8, 1, 2, 3, 5, 15, 4, 10, 6, 7, 0, 9, 13],
        [11, 10, 5, 14, 6, 13, 9, 0, 12, 8, 15, 3, 2, 4, 7, 1],
        [13, 7, 15, 4, 1, 2, 6, 14, 9, 11, 3, 0, 8, 5, 12, 10],
    ],
    [
        [2, 8, 11, 13, 15, 7, 6, 14, 3, 1, 9, 4, 0, 10, 12, 5],
        [1, 14, 2, 11, 4, 12, 3, 7, 6, 13, 10, 5, 15, 9, 0, 8],
        [4, 12, 7, 5, 1, 6, 9, 10, 0, 14, 13, 8, 2, 11, 3, 15],
        [11, 9, 5, 1, 12, 3, 13, 14, 6, 4, 7, 15, 2, 0, 8, 10],
    ],
]

# GF(2^8) reduction polynomials (Twofish, Section 3.3).
MDS_POLY = (1 << 8) + (1 << 6) + (1 << 5) + (1 << 3) + 1  # 0x0169
RS_POLY = (1 << 8) + (1 << 6) + (1 << 3) + (1 << 2) + 1  # 0x014D

# Rho = 0x01010101, the spacing between round constants (Section 5.2).
RHO = (1 << 24) + (1 << 16) + (1 << 8) + 1


def multgf(a, b, pol):
    """Multiply two bytes in GF(2^8) with reduction polynomial pol."""
    if b == 0:
        return 0
    p = 0
    while b != 0:
        if b & 1:
            p = p ^ a
        b = b >> 1
        a = a << 1
        if a > 255:
            a = a ^ pol
    return p


def matmulgf(mat, vec, pol):
    """Mix a byte vector with a matrix over GF(2^8), packing rows into a
    32-bit word (row 0 of the matrix = most significant byte)."""
    result = 0
    for v, row in enumerate(mat):
        new_val = 0
        for x, val in enumerate(row):
            new_val = new_val ^ multgf(val, vec[x], pol)
        result = result + new_val * 2 ** (8 * (len(mat) - 1 - v))
    return result


class Twofish(EncryptionBase):
    """Twofish cipher; 128-bit blocks with 128/192/256-bit keys."""
    def rotl(self, a, s, n):
        return ((a >> s) | (a << n - s)) % (2**n)

    def rotr(self, a, s, n):
        return ((a << s) | (a >> n - s)) % (2**n)

    subkeys = []

    sbox0 = []
    sbox1 = []
    sbox2 = []
    sbox3 = []

    def q(self, x, i=0):
        """Apply the q0/q1 4-bit permutation network to one byte."""
        a0 = int(x / 16)
        b0 = int(x % 16)
        a1 = a0 ^ b0
        b1 = a0 ^ self.rotl(b0, 1, 4)
        b1 = b1 ^ ((8 * a0) % 16)
        a1 = TQ[i][0][a1]
        b1 = TQ[i][1][b1]
        a2 = a1 ^ b1
        b2 = a1 ^ self.rotl(b1, 1, 4)
        b2 = b2 ^ ((8 * a1) % 16)
        a2 = TQ[i][2][a2]
        b2 = TQ[i][3][b2]
        return 16 * b2 + a2

    def g(self, x):
        """Key-dependent round function: the four keyed S-boxes XORed together."""
        x = [int((x / (2 ** (8 * i))) % (2**8)) for i in range(4)]
        return self.sbox0[x[0]] ^ self.sbox1[x[1]] ^ self.sbox2[x[2]] ^ self.sbox3[x[3]]

    def h(self, x, l0):
        """Interleave q permutations with the key vector, then mix through the MDS matrix."""
        x = [int((x / (2 ** (8 * i))) % (2**8)) for i in range(4)]
        if len(l0) == 4:
            x[0] = self.q(x[0], 1) ^ l0[3][0]
            x[1] = self.q(x[1], 0) ^ l0[3][1]
            x[2] = self.q(x[2], 0) ^ l0[3][2]
            x[3] = self.q(x[3], 1) ^ l0[3][3]
        if len(l0) >= 3:
            x[0] = self.q(x[0], 1) ^ l0[2][0]
            x[1] = self.q(x[1], 1) ^ l0[2][1]
            x[2] = self.q(x[2], 0) ^ l0[2][2]
            x[3] = self.q(x[3], 0) ^ l0[2][3]

        x[0] = self.q(x[0], 0) ^ l0[1][0]
        x[1] = self.q(x[1], 1) ^ l0[1][1]
        x[2] = self.q(x[2], 0) ^ l0[1][2]
        x[3] = self.q(x[3], 1) ^ l0[1][3]

        x[0] = self.q(x[0], 0) ^ l0[0][0]
        x[1] = self.q(x[1], 0) ^ l0[0][1]
        x[2] = self.q(x[2], 1) ^ l0[0][2]
        x[3] = self.q(x[3], 1) ^ l0[0][3]

        x[0] = self.q(x[0], 1)
        x[1] = self.q(x[1], 0)
        x[2] = self.q(x[2], 1)
        x[3] = self.q(x[3], 0)

        return self.mds_lt_m([x[0], x[1], x[2], x[3]])

    def mds_lt_m(self, vec):
        """Mix a 4-byte vector through the MDS matrix (Twofish, Section 2.2).
        Row v of the matrix lands in byte lane v; this is the little-endian
        companion of matmulgf."""
        result = 0
        for v, row in enumerate(MDS):
            new_val = 0
            for x, val in enumerate(row):
                new_val = new_val ^ multgf(val, vec[x], MDS_POLY)
            result = result + new_val * 2 ** (8 * v)
        return result

    def pht(self, a, b):
        """Pseudo-Hadamard Transform of two 32-bit words."""
        num1 = (a + b) % (2**32)
        num2 = (a + 2 * b) % (2**32)
        return num1, num2

    def generate_keys(self, key):
        """Derive subkeys and key S-boxes.

        The key is read as hex bytes; each four-byte group forms a 32-bit
        word with its first byte most significant (big-endian), matching the
        Twofish key expansion. Words for the rounds themselves are
        little-endian (see hex_to_words_le).
        """
        key = self.pad_key_hex(key, [32, 48, 64])
        key = self.hex_to_bin(key)

        m = [int(key[i : i + 8], 2) for i in range(0, len(key), 8)]
        s = []
        for t in range(0, len(m), 8):
            s.append(matmulgf(RS, m[t : t + 8], RS_POLY))
        l0 = []
        for l in s:
            l0.append([int((l / (2 ** (8 * (3 - i))) % (2**8))) for i in range(4)])
        l0 = l0[::-1]
        x = [0, 0, 0, 0]
        s0 = [None] * 256
        s1 = [None] * 256
        s2 = [None] * 256
        s3 = [None] * 256
        for i in range(256):
            if len(l0) == 4:
                x[0] = self.q(i, 1) ^ l0[3][0]
                x[1] = self.q(i, 0) ^ l0[3][1]
                x[2] = self.q(i, 0) ^ l0[3][2]
                x[3] = self.q(i, 1) ^ l0[3][3]
                x[0] = self.q(x[0], 1) ^ l0[2][0]
                x[1] = self.q(x[1], 1) ^ l0[2][1]
                x[2] = self.q(x[2], 0) ^ l0[2][2]
                x[3] = self.q(x[3], 0) ^ l0[2][3]
                x[0] = self.q(x[0], 0) ^ l0[1][0]
                x[1] = self.q(x[1], 1) ^ l0[1][1]
                x[2] = self.q(x[2], 0) ^ l0[1][2]
                x[3] = self.q(x[3], 1) ^ l0[1][3]

                x[0] = self.q(x[0], 0) ^ l0[0][0]
                x[1] = self.q(x[1], 0) ^ l0[0][1]
                x[2] = self.q(x[2], 1) ^ l0[0][2]
                x[3] = self.q(x[3], 1) ^ l0[0][3]

                x[0] = self.q(x[0], 1)
                x[1] = self.q(x[1], 0)
                x[2] = self.q(x[2], 1)
                x[3] = self.q(x[3], 0)

            if len(l0) == 3:
                x[0] = self.q(i, 1) ^ l0[2][0]
                x[1] = self.q(i, 1) ^ l0[2][1]
                x[2] = self.q(i, 0) ^ l0[2][2]
                x[3] = self.q(i, 0) ^ l0[2][3]
                x[0] = self.q(x[0], 0) ^ l0[1][0]
                x[1] = self.q(x[1], 1) ^ l0[1][1]
                x[2] = self.q(x[2], 0) ^ l0[1][2]
                x[3] = self.q(x[3], 1) ^ l0[1][3]

                x[0] = self.q(x[0], 0) ^ l0[0][0]
                x[1] = self.q(x[1], 0) ^ l0[0][1]
                x[2] = self.q(x[2], 1) ^ l0[0][2]
                x[3] = self.q(x[3], 1) ^ l0[0][3]

                x[0] = self.q(x[0], 1)
                x[1] = self.q(x[1], 0)
                x[2] = self.q(x[2], 1)
                x[3] = self.q(x[3], 0)

            if len(l0) == 2:
                x[0] = self.q(i, 0) ^ l0[1][0]
                x[1] = self.q(i, 1) ^ l0[1][1]
                x[2] = self.q(i, 0) ^ l0[1][2]
                x[3] = self.q(i, 1) ^ l0[1][3]
                x[0] = self.q(x[0], 0) ^ l0[0][0]
                x[1] = self.q(x[1], 0) ^ l0[0][1]
                x[2] = self.q(x[2], 1) ^ l0[0][2]
                x[3] = self.q(x[3], 1) ^ l0[0][3]

                x[0] = self.q(x[0], 1)
                x[1] = self.q(x[1], 0)
                x[2] = self.q(x[2], 1)
                x[3] = self.q(x[3], 0)

            # Each keyed S-box folds one q-permuted byte through the MDS
            # matrix (row v -> byte lane v), giving a 32-bit look-up.
            s0[i] = self.mds_lt_m([x[0], 0, 0, 0])
            s1[i] = self.mds_lt_m([0, x[1], 0, 0])
            s2[i] = self.mds_lt_m([0, 0, x[2], 0])
            s3[i] = self.mds_lt_m([0, 0, 0, x[3]])

        self.sbox0 = s0
        self.sbox1 = s1
        self.sbox2 = s2
        self.sbox3 = s3

        m_odd = []
        m_even = []
        for i in range(0, len(m), 4):
            q = (
                m[i] * 2 ** (8 * 3)
                + m[i + 1] * 2 ** (8 * 2)
                + m[i + 2] * 2 ** (8)
                + m[i + 3]
            )
            q = [int((q / (2 ** (8 * (3 - i))) % (2**8))) for i in range(4)]
            if int(i / 4) % 2 == 1:
                m_odd.append(q)
            else:
                m_even.append(q)
                # Round constants step by rho (see RHO).
        keys = []
        for i in range(20):
            a = self.h(2 * i * RHO, m_even)
            b = self.h((2 * i + 1) * RHO, m_odd)
            b = self.rotr(b, 8, 32)
            a, b = self.pht(a, b)
            b = self.rotr(b, 9, 32)
            keys.append(a)
            keys.append(b)
        self.subkeys = keys

    @staticmethod
    def hex_to_words_le(hex_str):
        """Split a 128-bit hex block into four 32-bit little-endian words.

        Twofish is little-endian: each 4-byte group is read with its
        least-significant byte first, so the hex block "54686174..." becomes
        the word 0x74616854.
        """
        data = bytes.fromhex(hex_str)
        return [int.from_bytes(data[i * 4 : i * 4 + 4], "little") for i in range(4)]

    @staticmethod
    def words_to_hex_le(words):
        """Serialize four 32-bit little-endian words back to a hex string."""
        return "".join((w & 0xFFFFFFFF).to_bytes(4, "little").hex() for w in words)

    def encrypt_block(self, plt):
        """Encrypt one 128-bit block given as 32 hex characters."""
        x = self.hex_to_words_le(plt)
        for i in range(4):
            x[i] = x[i] ^ self.subkeys[i]
        for i in range(16):
            nl0 = x[0]
            nl1 = x[1]
            x[0] = self.g(x[0])
            x[1] = self.g(self.rotr(x[1], 8, 32))
            x[0], x[1] = self.pht(x[0], x[1])
            x[0] = (x[0] + self.subkeys[2 * i + 8]) % (2**32)
            x[1] = (x[1] + self.subkeys[2 * i + 9]) % (2**32)
            x[2] = x[2] ^ x[0]
            x[2] = self.rotl(x[2], 1, 32)
            x[3] = self.rotr(x[3], 1, 32)
            x[3] = x[3] ^ x[1]

            x[0] = x[2]
            x[1] = x[3]
            x[2] = nl0
            x[3] = nl1
        x = [x[2], x[3], x[0], x[1]]

        for i in range(4):
            x[i] = x[i] ^ self.subkeys[4 + i]
        return self.words_to_hex_le(x)

    def decrypt_block(self, plt):
        """Decrypt one 128-bit block given as 32 hex characters."""
        x = self.hex_to_words_le(plt)
        for i in range(4):
            x[i] = x[i] ^ self.subkeys[4 + i]
        for i in range(16):
            nl0 = x[0]
            nl1 = x[1]
            x[0] = self.g(x[0])
            x[1] = self.g(self.rotr(x[1], 8, 32))
            x[0], x[1] = self.pht(x[0], x[1])
            x[0] = (x[0] + self.subkeys[2 * (15 - i) + 8]) % (2**32)
            x[1] = (x[1] + self.subkeys[2 * (15 - i) + 9]) % (2**32)
            x[2] = self.rotr(x[2], 1, 32)
            x[2] = x[2] ^ x[0]
            x[3] = x[3] ^ x[1]
            x[3] = self.rotl(x[3], 1, 32)

            x[0] = x[2]
            x[1] = x[3]
            x[2] = nl0
            x[3] = nl1
        x = [x[2], x[3], x[0], x[1]]
        for i in range(4):
            x[i] = x[i] ^ self.subkeys[i]
        return self.words_to_hex_le(x)

    def encrypt(self, plaintext, mode="ECB", padding="ISO 7816-4", iv=""):
        """Encrypt a plaintext hex string in the requested mode and padding."""
        return self.encrypt_mode(32, plaintext, mode, padding, iv)

    def decrypt(self, plaintext, mode="CBC", padding="ISO 7816-4", iv=""):
        """Decrypt a ciphertext hex string in the requested mode and padding."""
        return self.decrypt_mode(32, plaintext, mode, padding, iv)
