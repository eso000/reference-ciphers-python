"""Advanced Encryption Standard (FIPS-197), implemented step by step for teaching."""

from encryption_base import EncryptionBase

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

# Round counts per key size in 32-bit words (FIPS-197 Section 5.4).
AES_ROUNDS = {4: 11, 6: 13, 8: 15}

# Reduction polynomial x^8 + x^4 + x^3 + x + 1 used by xtime()/gmul().
XTIME_REDUCTION = 0x11B


def xtime(a):
    """Multiply byte a by 0x02 in GF(2^8); the building block of MixColumns."""

    a <<= 1
    if a & 0x100:
        a ^= XTIME_REDUCTION
    return a & 0xFF


def gmul(a, b):
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

    subkeys = []

    def sub_bytes(self, s):
        """Substitute each state byte through the AES S-box (FIPS-197 5.1.1)."""
        return [SBOX[int(x / 16)][int(x % 16)] for x in s]

    def inv_sub_bytes(self, s):
        """Inverse S-box substitution (FIPS-197 5.1.2)."""
        return [INV_SBOX[int(x / 16)][int(x % 16)] for x in s]

    def add_round_key(self, arr1, arr2):
        """XOR the state with a 16-byte round key."""
        return [arr1[i] ^ arr2[i] for i in range(len(arr1))]

    def generate_keys(self, key):
        """Expand a 128/192/256-bit hex key into the round-key schedule."""
        key = self.pad_key_hex(key, [32, 48, 64])
        keys = []
        s = bytes.fromhex(key)
        w = []
        for x in range(0, len(s), 4):
            w.append([s[x], s[x + 1], s[x + 2], s[x + 3]])
        n = len(w)
        rounds = AES_ROUNDS[n]
        rcon = [1, 0, 0, 0]
        for x in range(n, 4 * rounds):
            if x % n == 0:
                if x - n > 0:
                    rcon[0] = xtime(rcon[0])
                t = self.add_round_key(self.sub_bytes(self.rotl(w[len(w) - 1], 1)), rcon)
                w.append(self.add_round_key(w[len(w) - n], t))
            elif n > 6 and x % n == 4:
                w.append(self.add_round_key(w[len(w) - n], self.sub_bytes(w[len(w) - 1])))
            else:
                w.append(self.add_round_key(w[len(w) - n], w[len(w) - 1]))
        for i in range(0, len(w), 4):
            keys.append(w[i] + w[i + 1] + w[i + 2] + w[i + 3])
        self.subkeys = keys

    def inv_shift_rows(self, s):
        """Inverse of shift_rows, used by decryption."""
        for i in range(1, 4):
            row = [s[i], s[i + 4], s[i + 8], s[i + 12]]
            row = self.rotl(row, 4 - i)
            s[i] = row[0]
            s[i + 4] = row[1]
            s[i + 8] = row[2]
            s[i + 12] = row[3]
        return s

    def shift_rows(self, s):
        """Cyclically rotate each state row left by its row index."""
        for i in range(1, 4):
            row = [s[i], s[i + 4], s[i + 8], s[i + 12]]
            row = self.rotl(row, i)
            s[i] = row[0]
            s[i + 4] = row[1]
            s[i + 8] = row[2]
            s[i + 12] = row[3]
        return s

    def mix_rows(self, s):
        """Mix each state column with the circulant matrix over GF(2^8)."""
        m = [[2, 3, 1, 1], [1, 2, 3, 1], [1, 1, 2, 3], [3, 1, 1, 2]]
        return [
            gmul(m[i][0], s[4 * x])
            ^ gmul(m[i][1], s[1 + 4 * x])
            ^ gmul(m[i][2], s[2 + 4 * x])
            ^ gmul(m[i][3], s[3 + 4 * x])
            for x in range(4)
            for i in range(4)
        ]

    def inv_mix_rows(self, s):
        """Inverse of mix_rows, used by decryption."""
        m = [[14, 11, 13, 9], [9, 14, 11, 13], [13, 9, 14, 11], [11, 13, 9, 14]]
        return [
            gmul(m[i][0], s[4 * x])
            ^ gmul(m[i][1], s[1 + 4 * x])
            ^ gmul(m[i][2], s[2 + 4 * x])
            ^ gmul(m[i][3], s[3 + 4 * x])
            for x in range(4)
            for i in range(4)
        ]

    def encrypt_block(self, plt):
        """Encrypt one 128-bit block given as 32 hex characters."""
        plt = bytes.fromhex(plt)
        plt = self.add_round_key(plt, self.subkeys[0])
        for x in range(1, len(self.subkeys) - 1):
            plt = self.sub_bytes(plt)
            plt = self.shift_rows(plt)
            plt = self.mix_rows(plt)
            plt = self.add_round_key(plt, self.subkeys[x])
        plt = self.sub_bytes(plt)
        plt = self.shift_rows(plt)
        plt = self.add_round_key(plt, self.subkeys[-1])
        s = ""
        for x in plt:
            s = s + hex(x)[2:].zfill(2)
        return s

    def decrypt_block(self, plt):
        """Decrypt one 128-bit block given as 32 hex characters."""
        plt = bytes.fromhex(plt)
        l = len(self.subkeys)
        plt = self.add_round_key(plt, self.subkeys[l - 1])
        plt = self.inv_shift_rows(plt)
        plt = self.inv_sub_bytes(plt)
        for x in range(2, l):
            plt = self.add_round_key(plt, self.subkeys[l - x])
            plt = self.inv_mix_rows(plt)
            plt = self.inv_shift_rows(plt)
            plt = self.inv_sub_bytes(plt)
        plt = self.add_round_key(plt, self.subkeys[0])
        s = ""
        for x in plt:
            s = s + hex(x)[2:].zfill(2)
        return s

    def encrypt(self, plaintext, mode="CBC", padding="ISO 7816-4", iv=""):
        """Encrypt a plaintext hex string in the requested mode and padding."""
        return self.encrypt_mode(32, plaintext, mode, padding, iv)

    def decrypt(self, plaintext, mode="CBC", padding="ISO 7816-4", iv=""):
        """Decrypt a ciphertext hex string in the requested mode and padding."""
        return self.decrypt_mode(32, plaintext, mode, padding, iv)
