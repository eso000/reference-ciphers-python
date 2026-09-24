"""DES and 3DES (FIPS 46-3), implemented step by step for teaching."""

from encryption_base import EncryptionBase
from typing import Union

# Initial permutation IP (FIPS 46-3, Section 3.2.1): scatters the
# 64-bit block into left/right halves. Used by encrypt/decrypt_block.
IP = [
    58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7,
]

# Final permutation FP, the inverse of IP (FIPS 46-3, Section 3.2.2).
FP = [
    40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25,
]

# Expansion permutation E (FIPS 46-3, Section 3.2.2): widens the 32-bit
# right half to 48 bits before the round-key XOR. Used by f().
E = [
    32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11,
    12, 13, 12, 13, 14, 15, 16, 17, 16, 17, 18, 19, 20, 21, 20, 21,
    22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1,
]

# S-boxes (FIPS 46-3, Section 3.2.3). Each is a 4x16 table: the two
# outer bits of a 6-bit chunk pick the row, the four inner bits the
# column. Used by f().
SBOXES = [
    [
        [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
        [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
        [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
        [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13],
    ],
    [
        [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
        [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
        [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
        [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9],
    ],
    [
        [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
        [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
        [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
        [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12],
    ],
    [
        [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
        [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
        [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
        [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14],
    ],
    [
        [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
        [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
        [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
        [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3],
    ],
    [
        [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
        [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
        [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
        [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13],
    ],
    [
        [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
        [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
        [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
        [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12],
    ],
    [
        [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
        [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
        [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
        [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11],
    ],
]

# Key permutation choices: PC1 drops the 8 parity bits (Section 3.2.1),
# PC2 selects the 48 round-key bits (Section 3.2.2). Used by generate_keys.
PC1 = [
    57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2,
    59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36, 63, 55, 47, 39,
    31, 23, 15, 7, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37,
    29, 21, 13, 5, 28, 20, 12, 4,
]

PC2 = [
    14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4,
    26, 8, 16, 7, 27, 20, 13, 2, 41, 52, 31, 37, 47, 55, 30, 40,
    51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32,
]

# P permutation (FIPS 46-3, Section 3.2.2) applied to the S-box output. Used by f().
P = [
    16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10,
    2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25,
]


class DES(EncryptionBase):
    """DES cipher; 64-bit blocks with 16 hex-character keys."""

    def __init__(self):
        self.subkeys: list[int] = []

    def get_block_size(self) -> int:
        return 8  # 64 bits = 8 bytes

    def generate_keys(self, key: Union[bytes, str]) -> None:
        """Derive the 16 round subkeys from a 64-bit (8 byte) key."""
        if isinstance(key, str):
            key = self.hex_to_bytes(key)
        if len(key) < 8:
            key = self.pad(key, 8, "0")
        key_bits = self.permutate_int(int.from_bytes(key, "big"), PC1, width=64)
        left_key = key_bits >> 28
        right_key = key_bits & 0x0FFFFFFF
        subkeys = []
        for i in range(16):
            if i + 1 in (1, 2, 9, 16):
                shift = 1
            else:
                shift = 2
            left_key = self.rotl_int(left_key, shift, 28)
            right_key = self.rotl_int(right_key, shift, 28)
            combined = (left_key << 28) | right_key
            subkeys.append(self.permutate_int(combined, PC2, width=56))
        self.subkeys = subkeys

    def f(self, blk: int, subkey: int) -> int:
        """Feistel round function: expansion, key XOR, S-boxes, then the P permutation."""
        mixed = self.permutate_int(blk, E, width=32) ^ subkey
        sbox_out = 0
        for j in range(8):
            six = (mixed >> (48 - 6 * (j + 1))) & 0x3F
            row = ((six >> 4) & 2) | (six & 1)
            col = (six >> 1) & 0xF
            sbox_out = (sbox_out << 4) | SBOXES[j][row][col]
        return self.permutate_int(sbox_out, P, width=32)

    def encrypt_block(self, plaintext: bytes) -> bytes:
        """Encrypt one 64-bit block given as 8 bytes."""
        block = self.permutate_int(int.from_bytes(plaintext, "big"), IP, width=64)
        left = block >> 32
        right = block & 0xFFFFFFFF
        for i in range(16):
            left, right = right, left ^ self.f(right, self.subkeys[i])
        combined = (right << 32) | left
        result = self.permutate_int(combined, FP, width=64)
        return result.to_bytes(8, "big")

    def decrypt_block(self, ciphertext: bytes) -> bytes:
        """Decrypt one 64-bit block given as 8 bytes."""
        block = self.permutate_int(int.from_bytes(ciphertext, "big"), IP, width=64)
        left = block >> 32
        right = block & 0xFFFFFFFF
        for i in range(16):
            left, right = right, left ^ self.f(right, self.subkeys[15 - i])
        combined = (right << 32) | left
        result = self.permutate_int(combined, FP, width=64)
        return result.to_bytes(8, "big")


class TrippleDES(EncryptionBase):
    """Three-key triple DES: Encrypt-Decrypt-Encrypt over three DES instances."""

    def __init__(self):
        self.des1 = DES()
        self.des2 = DES()
        self.des3 = DES()

    def get_block_size(self) -> int:
        return 8  # 64 bits = 8 bytes

    def encrypt_block(self, plaintext: bytes) -> bytes:
        """Encrypt one 64-bit block given as 8 bytes."""
        pt = self.des1.encrypt_block(plaintext)
        pt = self.des2.decrypt_block(pt)
        return self.des3.encrypt_block(pt)

    def decrypt_block(self, ciphertext: bytes) -> bytes:
        """Decrypt one 64-bit block given as 8 bytes."""
        pt = self.des3.decrypt_block(ciphertext)
        pt = self.des2.encrypt_block(pt)
        return self.des1.decrypt_block(pt)

    def generate_keys(self, key: Union[bytes, str]) -> None:
        """Derive the 16 round subkeys from a 192-bit (24 byte) key."""
        if isinstance(key, str):
            key = self.hex_to_bytes(key)
        if len(key) < 24:
            key = self.pad(key, 24, "0")
        self.des1.generate_keys(key[0:8])
        self.des2.generate_keys(key[8:16])
        self.des3.generate_keys(key[16:24])