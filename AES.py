"""Advanced Encryption Standard (FIPS-197), implemented step by step for teaching."""

from encryption_base import EncryptionBase

# AES S-box tables (SBOX, INV_SBOX) are in the appendix at the end of this file.
# Round counts per key size in 32-bit words (FIPS-197 Section 5.4).
AES_ROUNDS = {4: 11, 6: 13, 8: 15}

# Reduction polynomial x^8 + x^4 + x^3 + x + 1 used by xtime()/gmul().
XTIME_REDUCTION = 0x11B


def xtime(a: int) -> int:
    """Multiply byte a by 0x02 in GF(2^8); the building block of MixColumns."""
    a <<= 1
    if a & 0x100:
        a ^= XTIME_REDUCTION
    return a & 0xFF


def gmul(a: int, b: int) -> int:
    """Multiply two bytes in GF(2^8) the Russian-peasant / xtime way."""
    out = 0
    while b:
        if b & 1:
            out ^= a
        a = xtime(a)
        b >>= 1
    return out


class AES(EncryptionBase):
    """AES cipher; supports 128/192/256-bit keys and 128-bit blocks."""

    def __init__(self):
        self.subkeys: list[list[int]] = []

    def get_block_size(self) -> int:
        return 16  # 128 bits = 16 bytes

    def sub_bytes(self, state: list[int]) -> list[int]:
        """Substitute each state byte through the AES S-box (FIPS-197 5.1.1)."""
        return [SBOX[b >> 4][b & 0xF] for b in state]

    def inv_sub_bytes(self, state: list[int]) -> list[int]:
        """Inverse S-box substitution (FIPS-197 5.1.2)."""
        return [INV_SBOX[b >> 4][b & 0xF] for b in state]

    def add_round_key(self, state: list[int], round_key: list[int]) -> list[int]:
        """XOR the state with a 16-byte round key."""
        return [state[i] ^ round_key[i] for i in range(16)]

    def generate_keys(self, key: bytes) -> None:
        """Expand a 128/192/256-bit key into the round-key schedule.

        Shorter keys are zero-padded up to the next valid size.
        """
        key_bytes = self.pad_key(self._as_bytes(key, "key"), [16, 24, 32])
        n_words = len(key_bytes) // 4
        rounds = AES_ROUNDS[n_words]

        w = []
        for i in range(0, len(key_bytes), 4):
            w.append(list(key_bytes[i:i+4]))

        rcon = [1, 0, 0, 0]
        for i in range(n_words, 4 * rounds):
            temp = w[-1].copy()
            if i % n_words == 0:
                if i > n_words:
                    rcon[0] = xtime(rcon[0])
                # RotWord
                temp = temp[1:] + temp[:1]
                # SubWord
                temp = [SBOX[b >> 4][b & 0xF] for b in temp]
                # Rcon
                temp[0] ^= rcon[0]
            elif n_words > 6 and i % n_words == 4:
                # SubWord for 256-bit keys
                temp = [SBOX[b >> 4][b & 0xF] for b in temp]
            w.append([w[i - n_words][j] ^ temp[j] for j in range(4)])

        # Convert to list of 16-byte round keys
        self.subkeys = []
        for i in range(0, len(w), 4):
            round_key = w[i] + w[i+1] + w[i+2] + w[i+3]
            self.subkeys.append(round_key)

    def shift_rows(self, state: list[int]) -> list[int]:
        """Cyclically rotate each state row left by its row index."""
        # State is column-major: [c0r0, c1r0, c2r0, c3r0, c0r1, ...]
        # Row 0: no shift
        # Row 1: shift left 1
        # Row 2: shift left 2
        # Row 3: shift left 3
        return [
            state[0], state[5], state[10], state[15],  # row 0
            state[4], state[9], state[14], state[3],   # row 1
            state[8], state[13], state[2], state[7],   # row 2
            state[12], state[1], state[6], state[11],  # row 3
        ]

    def inv_shift_rows(self, state: list[int]) -> list[int]:
        """Inverse of shift_rows, used by decryption."""
        return [
            state[0], state[13], state[10], state[7],   # row 0
            state[4], state[1], state[14], state[11],   # row 1
            state[8], state[5], state[2], state[15],    # row 2
            state[12], state[9], state[6], state[3],    # row 3
        ]

    def mix_columns(self, state: list[int]) -> list[int]:
        """Mix each state column with the circulant matrix over GF(2^8)."""
        out = [0] * 16
        for c in range(4):
            s0 = state[c*4]
            s1 = state[c*4 + 1]
            s2 = state[c*4 + 2]
            s3 = state[c*4 + 3]
            out[c*4] = gmul(2, s0) ^ gmul(3, s1) ^ s2 ^ s3
            out[c*4 + 1] = s0 ^ gmul(2, s1) ^ gmul(3, s2) ^ s3
            out[c*4 + 2] = s0 ^ s1 ^ gmul(2, s2) ^ gmul(3, s3)
            out[c*4 + 3] = gmul(3, s0) ^ s1 ^ s2 ^ gmul(2, s3)
        return out

    def inv_mix_columns(self, state: list[int]) -> list[int]:
        """Inverse of mix_columns, used by decryption."""
        out = [0] * 16
        for c in range(4):
            s0 = state[c*4]
            s1 = state[c*4 + 1]
            s2 = state[c*4 + 2]
            s3 = state[c*4 + 3]
            out[c*4] = gmul(14, s0) ^ gmul(11, s1) ^ gmul(13, s2) ^ gmul(9, s3)
            out[c*4 + 1] = gmul(9, s0) ^ gmul(14, s1) ^ gmul(11, s2) ^ gmul(13, s3)
            out[c*4 + 2] = gmul(13, s0) ^ gmul(9, s1) ^ gmul(14, s2) ^ gmul(11, s3)
            out[c*4 + 3] = gmul(11, s0) ^ gmul(13, s1) ^ gmul(9, s2) ^ gmul(14, s3)
        return out

    def encrypt_block(self, plaintext: bytes) -> bytes:
        """Encrypt one 128-bit block given as 16 bytes."""
        state = list(plaintext)
        state = self.add_round_key(state, self.subkeys[0])
        for round_key in self.subkeys[1:-1]:
            state = self.sub_bytes(state)
            state = self.shift_rows(state)
            state = self.mix_columns(state)
            state = self.add_round_key(state, round_key)
        state = self.sub_bytes(state)
        state = self.shift_rows(state)
        state = self.add_round_key(state, self.subkeys[-1])
        return bytes(state)

    def decrypt_block(self, ciphertext: bytes) -> bytes:
        """Decrypt one 128-bit block given as 16 bytes."""
        state = list(ciphertext)
        state = self.add_round_key(state, self.subkeys[-1])
        state = self.inv_shift_rows(state)
        state = self.inv_sub_bytes(state)
        for round_key in reversed(self.subkeys[1:-1]):
            state = self.add_round_key(state, round_key)
            state = self.inv_mix_columns(state)
            state = self.inv_shift_rows(state)
            state = self.inv_sub_bytes(state)
        state = self.add_round_key(state, self.subkeys[0])
        return bytes(state)
#
# ---- AES data tables (appendix) ----
#

# AES S-box (FIPS-197 Section 5.1.1). Row = high nibble, column = low nibble,
# so the byte value is the S-box index. Consumed by sub_bytes().
SBOX = [
    [99, 124, 119, 123, 242, 107, 111, 197, 48, 1, 103, 43, 254, 215, 171, 118],
    [202, 130, 201, 125, 250, 89, 71, 240, 173, 212, 162, 175, 156, 164, 114, 192],
    [183, 253, 147, 38, 54, 63, 247, 204, 52, 165, 229, 241, 113, 216, 49, 21],
    [4, 199, 35, 195, 24, 150, 5, 154, 7, 18, 128, 226, 235, 39, 178, 117],
    [9, 131, 44, 26, 27, 110, 90, 160, 82, 59, 214, 179, 41, 227, 47, 132],
    [83, 209, 0, 237, 32, 252, 177, 91, 106, 203, 190, 57, 74, 76, 88, 207],
    [208, 239, 170, 251, 67, 77, 51, 133, 69, 249, 2, 127, 80, 60, 159, 168],
    [81, 163, 64, 143, 146, 157, 56, 245, 188, 182, 218, 33, 16, 255, 243, 210],
    [205, 12, 19, 236, 95, 151, 68, 23, 196, 167, 126, 61, 100, 93, 25, 115],
    [96, 129, 79, 220, 34, 42, 144, 136, 70, 238, 184, 20, 222, 94, 11, 219],
    [224, 50, 58, 10, 73, 6, 36, 92, 194, 211, 172, 98, 145, 149, 228, 121],
    [231, 200, 55, 109, 141, 213, 78, 169, 108, 86, 244, 234, 101, 122, 174, 8],
    [186, 120, 37, 46, 28, 166, 180, 198, 232, 221, 116, 31, 75, 189, 139, 138],
    [112, 62, 181, 102, 72, 3, 246, 14, 97, 53, 87, 185, 134, 193, 29, 158],
    [225, 248, 152, 17, 105, 217, 142, 148, 155, 30, 135, 233, 206, 85, 40, 223],
    [140, 161, 137, 13, 191, 230, 66, 104, 65, 153, 45, 15, 176, 84, 187, 22],
]

# Inverse S-box (FIPS-197 Section 5.1.2). Consumed by inv_sub_bytes().
INV_SBOX = [
    [82, 9, 106, 213, 48, 54, 165, 56, 191, 64, 163, 158, 129, 243, 215, 251],
    [124, 227, 57, 130, 155, 47, 255, 135, 52, 142, 67, 68, 196, 222, 233, 203],
    [84, 123, 148, 50, 166, 194, 35, 61, 238, 76, 149, 11, 66, 250, 195, 78],
    [8, 46, 161, 102, 40, 217, 36, 178, 118, 91, 162, 73, 109, 139, 209, 37],
    [114, 248, 246, 100, 134, 104, 152, 22, 212, 164, 92, 204, 93, 101, 182, 146],
    [108, 112, 72, 80, 253, 237, 185, 218, 94, 21, 70, 87, 167, 141, 157, 132],
    [144, 216, 171, 0, 140, 188, 211, 10, 247, 228, 88, 5, 184, 179, 69, 6],
    [208, 44, 30, 143, 202, 63, 15, 2, 193, 175, 189, 3, 1, 19, 138, 107],
    [58, 145, 17, 65, 79, 103, 220, 234, 151, 242, 207, 206, 240, 180, 230, 115],
    [150, 172, 116, 34, 231, 173, 53, 133, 226, 249, 55, 232, 28, 117, 223, 110],
    [71, 241, 26, 113, 29, 41, 197, 137, 111, 183, 98, 14, 170, 24, 190, 27],
    [252, 86, 62, 75, 198, 210, 121, 32, 154, 219, 192, 254, 120, 205, 90, 244],
    [31, 221, 168, 51, 136, 7, 199, 49, 177, 18, 16, 89, 39, 128, 236, 95],
    [96, 81, 127, 169, 25, 181, 74, 13, 45, 229, 122, 159, 147, 201, 156, 239],
    [160, 224, 59, 77, 174, 42, 245, 176, 200, 235, 187, 60, 131, 83, 153, 97],
    [23, 43, 4, 126, 186, 119, 214, 38, 225, 105, 20, 99, 85, 33, 12, 125],
]
