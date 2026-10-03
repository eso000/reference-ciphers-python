"""Shared conversion and padding helpers for the teaching ciphers."""

from typing import List, Union


class EncryptionBase:
    """Base class supplying bytes/hex conversions, XOR, rotation,
    bit permutation, and block-mode scaffolding shared by the ciphers."""

    @staticmethod
    def bytes_to_hex(data: bytes) -> str:
        """Encode bytes as hex string."""
        return data.hex()

    @staticmethod
    def hex_to_bytes(hex_str: str) -> bytes:
        """Decode hex string to bytes."""
        return bytes.fromhex(hex_str)

    @staticmethod
    def bytes_to_bin(data: bytes) -> str:
        """Encode bytes as binary string (8 bits per byte)."""
        return "".join(f"{b:08b}" for b in data)

    @staticmethod
    def bin_to_bytes(bin_str: str) -> bytes:
        """Decode binary string (8 bits per byte) to bytes."""
        if len(bin_str) % 8 != 0:
            raise ValueError("Binary string length must be multiple of 8")
        return bytes(int(bin_str[i : i + 8], 2) for i in range(0, len(bin_str), 8))

    @staticmethod
    def bitwise_xor_bytes(data1: bytes, data2: bytes) -> bytes:
        """XOR two equal-length byte sequences."""
        min_len = min(len(data1), len(data2))
        return bytes(data1[i] ^ data2[i] for i in range(min_len))

    @staticmethod
    def bitwise_xor_bin(bin_str1: str, bin_str2: str) -> str:
        """XOR two equal-length binary strings."""
        min_len = min(len(bin_str1), len(bin_str2))
        return "".join(
            "0" if bin_str1[i] == bin_str2[i] else "1" for i in range(min_len)
        )

    @staticmethod
    def permutate_bin(bin_str: str, perm: List[int], start: int = 1) -> str:
        """Pick bits by the 1-based index list ``perm`` from a binary string."""
        return "".join(bin_str[i - start] for i in perm)

    @staticmethod
    def permutate_int(val: int, perm: List[int], width: int, start: int = 1) -> int:
        """Pick bits by the 1-based index list ``perm`` from ``val`` using
        shifts and masks only (no int-to-string conversion). ``width`` is the
        bit width of ``val``; the result has ``len(perm)`` bits."""
        out = 0
        for p in perm:
            src = width - 1 - (p - start)  # 1-based index -> shift from LSB
            out = (out << 1) | ((val >> src) & 1)
        return out

    @staticmethod
    def permutate_bytes(data: bytes, perm: List[int], start: int = 1) -> bytes:
        """Pick bytes by the 1-based index list ``perm`` from bytes."""
        return bytes(data[i - start] for i in perm)

    @staticmethod
    def rotl_int(val: int, shifts: int, width: int) -> int:
        """Cyclically rotate ``val`` left by ``shifts`` bits within ``width``."""
        shifts %= width
        mask = (1 << width) - 1
        return ((val << shifts) | (val >> (width - shifts))) & mask

    @staticmethod
    def rotl(val: int, shifts: int, width: int) -> int:
        """Rotate ``val`` left by ``shifts`` bits within ``width`` bits."""
        return ((val << shifts) | (val >> (width - shifts))) % (1 << width)

    @staticmethod
    def rotr(val: int, shifts: int, width: int) -> int:
        """Rotate ``val`` right by ``shifts`` bits within ``width`` bits."""
        return ((val >> shifts) | (val << (width - shifts))) % (1 << width)

    @staticmethod
    def rotl_str(s: str, shifts: int) -> str:
        """Cyclically rotate a string left by ``shifts`` positions."""
        shifts %= len(s)
        return s[shifts:] + s[:shifts]

    @staticmethod
    def rotr_str(s: str, shifts: int) -> str:
        """Cyclically rotate a string right by ``shifts`` positions."""
        shifts %= len(s)
        return s[-shifts:] + s[:-shifts]

    @staticmethod
    def rotl_list(lst: List, shifts: int) -> List:
        """Cyclically rotate a list left by ``shifts`` positions."""
        shifts %= len(lst)
        return lst[shifts:] + lst[:shifts]

    @staticmethod
    def rotr_list(lst: List, shifts: int) -> List:
        """Cyclically rotate a list right by ``shifts`` positions."""
        shifts %= len(lst)
        return lst[-shifts:] + lst[:-shifts]

    @staticmethod
    def shift_left_bin(bin_str: str, n: int) -> str:
        """Shift a binary string left by ``n`` bits, zero-filling on the right."""
        return bin_str[n:] + "0" * n

    @staticmethod
    def shift_right_bin(bin_str: str, n: int) -> str:
        """Shift a binary string right by ``n`` bits, zero-filling on the left."""
        return "0" * n + bin_str[:-n]

    def encrypt_block(self, plaintext: bytes) -> bytes:
        """Placeholder: single-block encryption, overridden by each cipher."""
        return plaintext

    def decrypt_block(self, ciphertext: bytes) -> bytes:
        """Placeholder: single-block decryption, overridden by each cipher."""
        return ciphertext

    def pad(self, data: bytes, length: int, typ: str = "bit") -> bytes:
        """Pad ``data`` up to ``length`` bytes using the requested scheme.

        Returns it unchanged when already long enough.
        """
        if len(data) == 0:
            data = b"\x00"
        shortfall = length - len(data)
        if shortfall <= 0:
            return data

        match typ:
            case "ISO 7816-4" | "bit":
                # ISO 7816-4 / bit padding: append 0x80 then zeros
                return data + b"\x80" + b"\x00" * (shortfall - 1)
            case "TBC":
                # Trailing bit complement - not common, simple implementation
                last_bit = data[-1] & 1
                return data + bytes([last_bit ^ 1]) * shortfall
            case "byt" | "0":
                # Zero padding
                return data + b"\x00" * shortfall
            case "PKCS":
                # PKCS#7: pad with byte value = padding length
                return data + bytes([shortfall]) * shortfall
            case "ANSI X9.23":
                # ANSI X9.23: zeros then padding length
                return data + b"\x00" * (shortfall - 1) + bytes([shortfall])
            case _:
                raise ValueError(f"Unknown padding type '{typ}'")

    def unpad(self, data: bytes, length: int, typ: str = "bit") -> bytes:
        """Remove the padding added by :meth:`pad` from ``data``.

        Returns ``data`` unchanged when the trailing bytes do not form a valid
        pad for ``typ``. Zero and character padding are ambiguous and left
        untouched.
        """
        if len(data) == 0:
            return data
        match typ:
            case "" | "0" | "byt" | "None":
                return data
            case "PKCS":
                pad_byte = data[-1]
                if pad_byte < 1 or pad_byte > length or pad_byte > len(data):
                    return data
                if data[-pad_byte:] == bytes([pad_byte]) * pad_byte:
                    return data[:-pad_byte]
                return data
            case "ANSI X9.23":
                pad_byte = data[-1]
                if pad_byte < 1 or pad_byte > length or pad_byte > len(data):
                    return data
                if data[-pad_byte:-1] == b"\x00" * (pad_byte - 1) and data[-1] == pad_byte:
                    return data[:-pad_byte]
                return data
            case "ISO 7816-4" | "bit":
                # Find last 0x80 preceded by zeros
                for i in range(len(data) - 1, max(-1, len(data) - length - 1), -1):
                    if data[i] == 0x80:
                        if data[i + 1 :] == b"\x00" * (len(data) - i - 1):
                            return data[:i]
                return data
            case "TBC":
                # Trailing bit complement - find where bits stop being complement
                last_bit = data[-1] & 1
                i = len(data) - 1
                while i >= max(0, len(data) - length) and (data[i] & 1) == last_bit:
                    i -= 1
                stripped = len(data) - 1 - i
                if 0 < stripped <= length and stripped % 1 == 0:
                    return data[: len(data) - stripped]
                return data
            case _:
                raise ValueError(f"Unknown padding type '{typ}'")

    def pad_key_hex(self, key: str, sizes: List[int]) -> str:
        """Pad a hex key to the first allowed ``sizes`` value (in hex characters)
        that fits it, or truncate it to the largest size."""
        for size in sizes:
            if len(key) <= size:
                return self.pad(bytes.fromhex(key), size // 2, "0").hex()
        return key[: sizes[-1]]

    def encrypt_mode(
        self,
        block_size: int,
        plaintext: bytes,
        mode: str = "CBC",
        padding: str = "",
        iv: bytes = b"",
    ) -> bytes:
        """Split the plaintext into blocks and encrypt them in the
        requested mode (ECB or CBC). Block size is in bytes."""
        blocks = [
            plaintext[i : i + block_size] for i in range(0, len(plaintext), block_size)
        ]
        if len(blocks) == 0:
            blocks = [self.pad(plaintext, block_size, padding)]
        elif len(blocks[-1]) < block_size:
            blocks[-1] = self.pad(blocks[-1], block_size, padding)

        match mode:
            case "ECB":
                result = bytearray()
                for block in blocks:
                    result.extend(self.encrypt_block(block))
                return bytes(result)
            case "CBC":
                result = bytearray()
                if len(iv) != block_size:
                    iv = self.pad(iv, block_size, padding)
                for block in blocks:
                    xored = self.bitwise_xor_bytes(block, iv)
                    encrypted = self.encrypt_block(xored)
                    iv = encrypted
                    result.extend(encrypted)
                return bytes(result)
            case "PCBC":
                result = bytearray()
                if len(iv) != block_size:
                    iv = self.pad(iv, block_size, padding)
                for block in blocks:
                    encrypted = self.encrypt_block(self.bitwise_xor_bytes(block, iv))
                    iv = self.bitwise_xor_bytes(block, encrypted)
                    result.extend(encrypted)
                return bytes(result)
            case "CFB":
                result = bytearray()
                if len(iv) != block_size:
                    iv = self.pad(iv, block_size, padding)
                for block in blocks:
                    encrypted = self.bitwise_xor_bytes(self.encrypt_block(iv), block)
                    iv = encrypted
                    result.extend(encrypted)
                return bytes(result)
            case "OFB":
                result = bytearray()
                if len(iv) != block_size:
                    iv = self.pad(iv, block_size, padding)
                for block in blocks:
                    iv = self.encrypt_block(iv)
                    result.extend(self.bitwise_xor_bytes(block, iv))
                return bytes(result)
            case "CTR":
                result = bytearray()
                if len(iv) != block_size:
                    iv = self.pad(iv, block_size, padding)
                counter = int.from_bytes(iv, "big")
                for block in blocks:
                    keystream = self.encrypt_block(
                        counter.to_bytes(block_size, "big")
                    )
                    counter += 1
                    result.extend(self.bitwise_xor_bytes(block, keystream))
                return bytes(result)
            case _:
                raise ValueError(f"Unknown mode '{mode}'")

    def decrypt_mode(
        self,
        block_size: int,
        ciphertext: bytes,
        mode: str = "CBC",
        padding: str = "",
        iv: bytes = b"",
    ) -> bytes:
        """Split the ciphertext into blocks and decrypt them in the
        requested mode (ECB or CBC). Block size is in bytes."""
        blocks = [
            ciphertext[i : i + block_size]
            for i in range(0, len(ciphertext), block_size)
        ]
        match mode:
            case "ECB":
                result = bytearray()
                for block in blocks:
                    result.extend(self.decrypt_block(block))
                return self.unpad(bytes(result), block_size, padding)
            case "CBC":
                result = bytearray()
                if len(iv) != block_size:
                    iv = self.pad(iv, block_size, padding)
                for block in blocks:
                    decrypted = self.decrypt_block(block)
                    xored = self.bitwise_xor_bytes(decrypted, iv)
                    iv = block
                    result.extend(xored)
                return self.unpad(bytes(result), block_size, padding)
            case "PCBC":
                result = bytearray()
                if len(iv) != block_size:
                    iv = self.pad(iv, block_size, padding)
                for block in blocks:
                    decrypted = self.bitwise_xor_bytes(self.decrypt_block(block), iv)
                    iv = self.bitwise_xor_bytes(block, decrypted)
                    result.extend(decrypted)
                return self.unpad(bytes(result), block_size, padding)
            case "CFB":
                result = bytearray()
                if len(iv) != block_size:
                    iv = self.pad(iv, block_size, padding)
                for block in blocks:
                    decrypted = self.bitwise_xor_bytes(self.encrypt_block(iv), block)
                    iv = block
                    result.extend(decrypted)
                return self.unpad(bytes(result), block_size, padding)
            case "OFB":
                result = bytearray()
                if len(iv) != block_size:
                    iv = self.pad(iv, block_size, padding)
                for block in blocks:
                    iv = self.encrypt_block(iv)
                    result.extend(self.bitwise_xor_bytes(block, iv))
                return self.unpad(bytes(result), block_size, padding)
            case "CTR":
                result = bytearray()
                if len(iv) != block_size:
                    iv = self.pad(iv, block_size, padding)
                counter = int.from_bytes(iv, "big")
                for block in blocks:
                    keystream = self.encrypt_block(
                        counter.to_bytes(block_size, "big")
                    )
                    counter += 1
                    result.extend(self.bitwise_xor_bytes(block, keystream))
                return self.unpad(bytes(result), block_size, padding)
            case _:
                raise ValueError(f"Unknown mode '{mode}'")

    def encrypt_hex(
        self, plaintext: str, mode: str = "CBC", padding: str = "", iv: str = ""
    ) -> str:
        """Encrypt a hex plaintext string, returning hex ciphertext."""
        pt_bytes = self.hex_to_bytes(plaintext)
        iv_bytes = self.hex_to_bytes(iv) if iv else b""
        block_size = self.get_block_size()
        ct_bytes = self.encrypt_mode(block_size, pt_bytes, mode, padding, iv_bytes)
        return self.bytes_to_hex(ct_bytes)

    def decrypt_hex(
        self, ciphertext: str, mode: str = "CBC", padding: str = "", iv: str = ""
    ) -> str:
        """Decrypt a hex ciphertext string, returning hex plaintext."""
        ct_bytes = self.hex_to_bytes(ciphertext)
        iv_bytes = self.hex_to_bytes(iv) if iv else b""
        block_size = self.get_block_size()
        pt_bytes = self.decrypt_mode(block_size, ct_bytes, mode, padding, iv_bytes)
        return self.bytes_to_hex(pt_bytes)

    def get_block_size(self) -> int:
        """Return block size in bytes. Override in subclass."""
        raise NotImplementedError("Subclass must implement get_block_size()")

    def encrypt(
        self,
        plaintext: Union[bytes, str],
        mode: str = "CBC",
        padding: str = "ISO 7816-4",
        iv: Union[bytes, str] = b"",
    ) -> Union[bytes, str]:
        """Encrypt plaintext (bytes or hex string) in the requested mode and padding."""
        if isinstance(plaintext, str):
            return self.encrypt_hex(
                plaintext, mode, padding, iv if isinstance(iv, str) else iv.hex()
            )
        iv_bytes = (
            iv if isinstance(iv, bytes) else (self.hex_to_bytes(iv) if iv else b"")
        )
        block_size = self.get_block_size()
        return self.encrypt_mode(block_size, plaintext, mode, padding, iv_bytes)

    def decrypt(
        self,
        ciphertext: Union[bytes, str],
        mode: str = "CBC",
        padding: str = "ISO 7816-4",
        iv: Union[bytes, str] = b"",
    ) -> Union[bytes, str]:
        """Decrypt ciphertext (bytes or hex string) in the requested mode and padding."""
        if isinstance(ciphertext, str):
            return self.decrypt_hex(
                ciphertext, mode, padding, iv if isinstance(iv, str) else iv.hex()
            )
        iv_bytes = (
            iv if isinstance(iv, bytes) else (self.hex_to_bytes(iv) if iv else b"")
        )
        block_size = self.get_block_size()
        return self.decrypt_mode(block_size, ciphertext, mode, padding, iv_bytes)
