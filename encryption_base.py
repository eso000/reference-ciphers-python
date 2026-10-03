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

    @staticmethod
    def mode_needs_padding(mode: str) -> bool:
        """Return True for modes that only work on whole blocks (ECB, CBC,
        PCBC) and False for the keystream modes (CFB, OFB, CTR), which handle
        a short final block by truncating the keystream."""
        match mode:
            case "ECB" | "CBC" | "PCBC":
                return True
            case "CFB" | "OFB" | "CTR":
                return False
            case _:
                raise ValueError(f"Unknown mode '{mode}'")

    def pad_for_mode(
        self, data: bytes, block_size: int, mode: str, padding: str = ""
    ) -> bytes:
        """Pad a whole message for ``mode``; keystream modes return it as is.

        Block modes always receive padding, even when ``data`` is already
        block-aligned (1 to ``block_size`` bytes, a full extra block when
        aligned), so :meth:`unpad_for_mode` can always remove it unambiguously.
        Zero padding ("0"/"byt") is the exception: it only fills to the next
        block boundary and cannot be removed again. ``padding`` of "" or "None"
        means no padding, so ``data`` must already be block-aligned.
        """
        if not self.mode_needs_padding(mode):
            return data
        match padding:
            case "" | "None":
                if len(data) % block_size:
                    raise ValueError(
                        f"{mode} needs a multiple of {block_size} bytes "
                        "or a padding scheme"
                    )
                return data
            case "0" | "byt":
                return data + b"\x00" * (-len(data) % block_size)
        count = block_size - len(data) % block_size
        match padding:
            case "PKCS":
                return data + bytes([count]) * count
            case "ANSI X9.23":
                return data + b"\x00" * (count - 1) + bytes([count])
            case "ISO 7816-4" | "bit":
                return data + b"\x80" + b"\x00" * (count - 1)
            case "TBC":
                # Trailing bit complement: fill with the inverse of the last bit
                fill = b"\x00" if data and data[-1] & 1 else b"\xff"
                return data + fill * count
            case _:
                raise ValueError(f"Unknown padding type '{padding}'")

    def unpad_for_mode(
        self, data: bytes, block_size: int, mode: str, padding: str = ""
    ) -> bytes:
        """Remove the padding added by :meth:`pad_for_mode`.

        Keystream modes, unpadded block modes and zero padding return ``data``
        unchanged. Malformed padding raises ``ValueError``.
        """
        if not self.mode_needs_padding(mode):
            return data
        match padding:
            case "" | "None" | "0" | "byt":
                return data
            case "PKCS" | "ANSI X9.23":
                count = data[-1] if data else 0
                if not 1 <= count <= min(block_size, len(data)):
                    raise ValueError("Invalid padding")
                body = data[-count:-1] if padding == "ANSI X9.23" else data[-count:]
                filler = b"\x00" if padding == "ANSI X9.23" else bytes([count])
                if body != filler * len(body):
                    raise ValueError("Invalid padding")
                return data[:-count]
            case "ISO 7816-4" | "bit":
                tail = data[-block_size:]
                stripped = tail.rstrip(b"\x00")
                if not stripped or stripped[-1] != 0x80:
                    raise ValueError("Invalid padding")
                return data[: len(data) - len(tail) + len(stripped) - 1]
            case "TBC":
                tail = data[-block_size:]
                if not tail or tail[-1] not in (0x00, 0xFF):
                    raise ValueError("Invalid padding")
                count = len(tail) - len(tail.rstrip(tail[-1:]))
                return data[: len(data) - count]
            case _:
                raise ValueError(f"Unknown padding type '{padding}'")

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
        requested mode. Block size is in bytes. Block modes (ECB, CBC, PCBC) are
        padded per ``padding``; CFB, OFB and CTR are not padded."""
        plaintext = self.pad_for_mode(plaintext, block_size, mode, padding)
        blocks = [
            plaintext[i : i + block_size] for i in range(0, len(plaintext), block_size)
        ]

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
        requested mode. Block size is in bytes. Block modes (ECB, CBC, PCBC) are
        padded per ``padding``; CFB, OFB and CTR are not padded."""
        if self.mode_needs_padding(mode) and len(ciphertext) % block_size:
            raise ValueError(
                f"{mode} ciphertext must be a multiple of {block_size} bytes"
            )
        blocks = [
            ciphertext[i : i + block_size]
            for i in range(0, len(ciphertext), block_size)
        ]
        match mode:
            case "ECB":
                result = bytearray()
                for block in blocks:
                    result.extend(self.decrypt_block(block))
                return self.unpad_for_mode(bytes(result), block_size, mode, padding)
            case "CBC":
                result = bytearray()
                if len(iv) != block_size:
                    iv = self.pad(iv, block_size, padding)
                for block in blocks:
                    decrypted = self.decrypt_block(block)
                    xored = self.bitwise_xor_bytes(decrypted, iv)
                    iv = block
                    result.extend(xored)
                return self.unpad_for_mode(bytes(result), block_size, mode, padding)
            case "PCBC":
                result = bytearray()
                if len(iv) != block_size:
                    iv = self.pad(iv, block_size, padding)
                for block in blocks:
                    decrypted = self.bitwise_xor_bytes(self.decrypt_block(block), iv)
                    iv = self.bitwise_xor_bytes(block, decrypted)
                    result.extend(decrypted)
                return self.unpad_for_mode(bytes(result), block_size, mode, padding)
            case "CFB":
                result = bytearray()
                if len(iv) != block_size:
                    iv = self.pad(iv, block_size, padding)
                for block in blocks:
                    decrypted = self.bitwise_xor_bytes(self.encrypt_block(iv), block)
                    iv = block
                    result.extend(decrypted)
                return self.unpad_for_mode(bytes(result), block_size, mode, padding)
            case "OFB":
                result = bytearray()
                if len(iv) != block_size:
                    iv = self.pad(iv, block_size, padding)
                for block in blocks:
                    iv = self.encrypt_block(iv)
                    result.extend(self.bitwise_xor_bytes(block, iv))
                return self.unpad_for_mode(bytes(result), block_size, mode, padding)
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
                return self.unpad_for_mode(bytes(result), block_size, mode, padding)
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
