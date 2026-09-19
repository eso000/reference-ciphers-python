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


def bits_to_int(bits: str) -> int:
    """Convert binary string to integer."""
    return int(bits, 2)


def int_to_bits(val: int, length: int) -> str:
    """Convert integer to binary string of given length."""
    return format(val, f'0{length}b')


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
        key_bits = self.bytes_to_bin(key)
        key_bits = self.permutate_bin(key_bits, PC1)
        left_key = key_bits[0:28]
        right_key = key_bits[28:56]
        subkeys = []
        for i in range(16):
            if i + 1 in (1, 2, 9, 16):
                shift = 1
            else:
                shift = 2
            left_key = self.rotl_str(left_key, shift)
            right_key = self.rotl_str(right_key, shift)
            combined = left_key + right_key
            subkey_bits = self.permutate_bin(combined, PC2)
            subkeys.append(bits_to_int(subkey_bits))
        self.subkeys = subkeys

    def f(self, blk_bits: str, subkey: int) -> str:
        """Feistel round function: expansion, key XOR, S-boxes, then the P permutation."""
        expanded = self.permutate_bin(blk_bits, E)
        expanded_int = bits_to_int(expanded)
        mixed = expanded_int ^ subkey
        mixed_bits = int_to_bits(mixed, 48)
        sbox_out = ""
        for j in range(8):
            six = mixed_bits[j * 6:j * 6 + 6]
            row = int(six[0] + six[5], 2)
            col = int(six[1:5], 2)
            sbox_out += format(SBOXES[j][row][col], '04b')
        return self.permutate_bin(sbox_out, P)

    def encrypt_block(self, plaintext: bytes) -> bytes:
        """Encrypt one 64-bit block given as 8 bytes."""
        blk_bits = self.bytes_to_bin(plaintext)
        blk_bits = self.permutate_bin(blk_bits, IP)
        left = blk_bits[0:32]
        right = blk_bits[32:64]
        for i in range(16):
            new_left = right
            right = self.f(right, self.subkeys[i])
            new_right = int_to_bits(int(left, 2) ^ int(right, 2), 32)
            left = new_left
            right = new_right
        combined = right + left
        result_bits = self.permutate_bin(combined, FP)
        return self.bin_to_bytes(result_bits)

    def decrypt_block(self, ciphertext: bytes) -> bytes:
        """Decrypt one 64-bit block given as 8 bytes."""
        blk_bits = self.bytes_to_bin(ciphertext)
        blk_bits = self.permutate_bin(blk_bits, IP)
        left = blk_bits[0:32]
        right = blk_bits[32:64]
        for i in range(16):
            new_left = right
            right = self.f(right, self.subkeys[15 - i])
            new_right = int_to_bits(int(left, 2) ^ int(right, 2), 32)
            left = new_left
            right = new_right
        combined = right + left
        result_bits = self.permutate_bin(combined, FP)
        return self.bin_to_bytes(result_bits)


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