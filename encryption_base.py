"""Shared conversion and padding helpers for the teaching ciphers."""


class EncryptionBase:
    """Base class supplying string/binary/hex conversions, XOR, rotation,
    bit permutation, and block-mode scaffolding shared by the ciphers."""

    def string_to_bin(self, s):
        """Encode each character as an 8-bit binary string."""
        return "".join([bin(ord(x))[2:].zfill(8) for x in s])

    def bin_to_string(self, s):
        """Decode 8-bit chunks back to characters, skipping byte values 0-239."""
        result = ""
        while len(s) != 0:
            if int(s[0:8], 2) > 0 and int(s[0:8], 2) < 240:
                result = result + chr(int(s[0:8], 2))
            s = s[8:]
        return result

    def string_to_hex(self, s):
        """Encode each character as its two-hex-digit code."""
        result = ""
        for x in s:
            result = result + hex(ord(x))[2:].zfill(2)
        return result

    @staticmethod
    def hex_to_bin(s):
        """Expand a hex string into its binary representation."""
        mp = {
            "0": "0000",
            "1": "0001",
            "2": "0010",
            "3": "0011",
            "4": "0100",
            "5": "0101",
            "6": "0110",
            "7": "0111",
            "8": "1000",
            "9": "1001",
            "A": "1010",
            "B": "1011",
            "C": "1100",
            "D": "1101",
            "E": "1110",
            "F": "1111",
            "a": "1010",
            "b": "1011",
            "c": "1100",
            "d": "1101",
            "e": "1110",
            "f": "1111",
        }
        return "".join([mp[si] for si in s])

    @staticmethod
    def bin_to_hex(s):
        """Group a binary string into nibbles and render them as hex."""
        mp = {
            "0000": "0",
            "0001": "1",
            "0010": "2",
            "0011": "3",
            "0100": "4",
            "0101": "5",
            "0110": "6",
            "0111": "7",
            "1000": "8",
            "1001": "9",
            "1010": "a",
            "1011": "b",
            "1100": "c",
            "1101": "d",
            "1110": "e",
            "1111": "f",
        }
        return "".join([mp[s[i : i + 4]] for i in range(0, len(s), 4)])

    @staticmethod
    def bin_to_hex_le(s):
        """Eight bits -> two hex digits, each nibble reversed (little-endian)."""
        mp = {
            "0000": "0",
            "0001": "1",
            "0010": "2",
            "0011": "3",
            "0100": "4",
            "0101": "5",
            "0110": "6",
            "0111": "7",
            "1000": "8",
            "1001": "9",
            "1010": "a",
            "1011": "b",
            "1100": "c",
            "1101": "d",
            "1110": "e",
            "1111": "f",
        }
        return "".join(
            [
                mp[s[i + 4 : i + 8][::-1]] + mp[s[i : i + 4][::-1]]
                for i in range(0, len(s), 8)
            ]
        )

    @staticmethod
    def hex_to_bin_le(s):
        """Two hex digits -> eight bits, each nibble reversed (little-endian)."""
        mp = {
            "0": "0000",
            "1": "0001",
            "2": "0010",
            "3": "0011",
            "4": "0100",
            "5": "0101",
            "6": "0110",
            "7": "0111",
            "8": "1000",
            "9": "1001",
            "A": "1010",
            "B": "1011",
            "C": "1100",
            "D": "1101",
            "E": "1110",
            "F": "1111",
            "a": "1010",
            "b": "1011",
            "c": "1100",
            "d": "1101",
            "e": "1110",
            "f": "1111",
        }
        return "".join(
            [mp[s[i + 1]][::-1] + mp[s[i]][::-1] for i in range(0, len(s), 2)]
        )

    @staticmethod
    def bitwise_xor(bit_string1, bit_string2):
        """XOR two equal-length binary strings, character by character."""
        min_length = min(len(bit_string1), len(bit_string2))
        result = ""
        for i in range(min_length):
            if bit_string1[i] == bit_string2[i]:
                result += "0"
            else:
                result += "1"
        return result

    @staticmethod
    def permutate(bit_string, perm, start=1):
        """Pick bits by the 1-based index list ``perm`` from a binary string."""
        return "".join([bit_string[i - start] for i in perm])

    @staticmethod
    def rotl(s, shifts):
        """Cyclically rotate a string or list left by ``shifts`` positions."""
        if isinstance(s, str):
            for _ in range(shifts):
                s = s[1 : len(s)] + s[0]
            return s
        if isinstance(s, list):
            return s[shifts:] + s[:shifts]
        raise TypeError(
            f"rotl expects str or list, got {type(s).__name__}"
        )

    @staticmethod
    def rotr(s, shifts):
        """Cyclically rotate a string or list right by ``shifts`` positions."""
        if isinstance(s, str):
            for _ in range(shifts):
                s = s[len(s) - 1] + s[0 : len(s) - 1]
            return s
        if isinstance(s, list):
            result = []
            for _ in range(shifts):
                for j in range(1, len(s)):
                    result.append(s[j])
                result.append(s[0])
                s = result
                result = []
            return s
        raise TypeError(
            f"rotr expects str or list, got {type(s).__name__}"
        )

    def encrypt_block(self, plt):
        """Placeholder: single-block encryption, overridden by each cipher."""
        return plt

    def decrypt_block(self, plt):
        """Placeholder: single-block decryption, overridden by each cipher."""
        return plt

    def pad(self, st, leng, typ="bit"):
        """Pad a hex string ``st`` up to length ``leng`` (in hex characters)
        using the requested scheme. Returns it unchanged when already long."""
        if len(st) == 0:
            st = "00"
        if len(st) % 2 == 1:
            st += "0"
        shortfall = leng - len(st)
        if shortfall <= 0:
            return st
        if typ == "bit":
            st = self.hex_to_bin(st)
            shortfall = shortfall * 4
            st = st + "1"
            for _ in range(1, shortfall):
                st = st + "0"
            return self.bin_to_hex(st)
        if typ == "TBC":
            st = self.hex_to_bin(st)
            shortfall = shortfall * 4
            if st[len(st) - 1] == "1":
                c = "0"
            else:
                c = "1"
            for _ in range(0, shortfall):
                st = st + c
            return self.bin_to_hex(st)
        if typ == "byt":
            for _ in range(0, int(shortfall / 2)):
                st = st + "00"
            return st
        if typ == "ISO 7816-4":
            st = st + "80"
            for _ in range(1, int(shortfall / 2)):
                st = st + "00"
            return st
        if typ == "PKCS":
            count = int(shortfall / 2)
            c = hex(count)[2:].zfill(2)
            for _ in range(count):
                st = st + c
            return st
        if typ == "ANSI X9.23":
            count = int(shortfall / 2)
            c = hex(count)[2:].zfill(2)
            for _ in range(count - 1):
                st = st + "00"
            st = st + c
            return st
        if typ == "0":
            for _ in range(0, int(shortfall)):
                st = st + "0"
            return st
        raise ValueError(f"Unknown padding type '{typ}'")

    def unpad(self, st, leng, typ="bit"):
        """Remove the padding added by :meth:`pad` from a hex string.

        Returns ``st`` unchanged when the trailing bytes do not form a valid
        pad for ``typ``. Zero and character padding are ambiguous and left
        untouched, mirroring the C/C++ reference implementations.
        """
        if typ in ("", "0", "byt", "None"):
            return st
        if typ == "PKCS":
            if len(st) < 2:
                return st
            count = st[-2:]
            n = int(count, 16)
            if n < 1 or n * 2 > len(st) or n * 2 > leng:
                return st
            if st[-2 * n :].lower() == count.lower() * n:
                return st[: -2 * n]
            return st
        if typ == "ANSI X9.23":
            if len(st) < 2:
                return st
            count = st[-2:]
            n = int(count, 16)
            if n < 1 or n * 2 > len(st) or n * 2 > leng:
                return st
            if st[-2:].lower() != count.lower():
                return st
            if st[-2 * n : -2].lower() == "00" * (n - 1):
                return st[: -2 * n]
            return st
        if typ in ("ISO 7816-4", "bit"):
            limit = max(0, len(st) - leng)
            i = len(st) - 2
            while i >= limit and st[i : i + 2] == "00":
                i -= 2
            if i >= limit and st[i : i + 2].lower() == "80":
                return st[:i]
            return st
        if typ == "TBC":
            bits = self.hex_to_bin(st)
            if len(bits) == 0:
                return st
            limit = max(0, len(bits) - leng * 4)
            last = bits[-1]
            i = len(bits) - 1
            while i >= limit and bits[i] == last:
                i -= 1
            stripped = len(bits) - 1 - i
            if 0 < stripped <= leng * 4 and stripped % 4 == 0:
                return self.bin_to_hex(bits[: len(bits) - stripped])
            return st
        raise ValueError(f"Unknown padding type '{typ}'")

    def pad_key_hex(self, key, sizes):
        """Pad a hex key to the first allowed ``sizes`` value (in hex
        characters) that fits it, or truncate it to the largest size."""
        for size in sizes:
            if len(key) <= size:
                return self.pad(key, size, "0")
        return key[0 : sizes[-1]]

    @staticmethod
    def shift_left(bit_string, n):
        """Shift a binary string left by ``n`` bits, zero-filling on the right."""
        for _ in range(n):
            bit_string = bit_string[1 : len(bit_string)] + "0"
        return bit_string

    @staticmethod
    def shift_right(bit_string, n):
        """Shift a binary string right by ``n`` bits, zero-filling on the left."""
        for _ in range(n):
            bit_string = "0" + bit_string[0 : len(bit_string) - 1]
        return bit_string

    def encrypt_mode(self, block_size, plt, mode="CBC", padding="", iv=""):
        """Split the hex plaintext into blocks and encrypt them in the
        requested mode (ECB or CBC)."""
        blocks = [
            plt[i : i + block_size] for i in range(0, len(plt), block_size)
        ]
        if len(blocks) == 0:
            blocks = [self.pad(plt, block_size, padding)]
        elif len(blocks[-1]) < block_size:
            blocks[len(blocks) - 1] = self.pad(
                blocks[len(blocks) - 1], block_size, padding
            )

        if mode == "ECB":
            result = ""
            for block in blocks:
                result = result + self.encrypt_block(block)
            return result
        if mode == "CBC":
            result = ""
            if len(iv) != block_size:
                iv = self.pad(iv, block_size, padding)
            for block in blocks:
                nb = self.bitwise_xor(
                    self.hex_to_bin(block), self.hex_to_bin(iv)
                )
                nb = self.encrypt_block(self.bin_to_hex(nb))
                iv = nb
                result = result + nb
            return result
        raise ValueError(f"Unknown mode '{mode}'")

    def decrypt_mode(self, block_size, plt, mode="CBC", padding="", iv=""):
        """Split the hex ciphertext into blocks and decrypt them in the
        requested mode (ECB or CBC)."""
        blocks = [
            plt[i : i + block_size] for i in range(0, len(plt), block_size)
        ]
        if mode == "ECB":
            result = ""
            for block in blocks:
                result = result + self.decrypt_block(block)
            return self.unpad(result, block_size, padding)
        if mode == "CBC":
            result = ""
            if len(iv) != block_size:
                iv = self.pad(iv, block_size, padding)
            for block in blocks:
                nb = self.decrypt_block(block)
                nb = self.bitwise_xor(self.hex_to_bin(nb), self.hex_to_bin(iv))
                nb = self.bin_to_hex(nb)
                iv = block
                result = result + nb
            return self.unpad(result, block_size, padding)
        raise ValueError(f"Unknown mode '{mode}'")
