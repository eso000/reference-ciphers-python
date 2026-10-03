"""Shared conversion and padding helpers for the teaching ciphers."""

from typing import List


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

    def pad_key(self, key: bytes, sizes: List[int]) -> bytes:
        """Zero-pad ``key`` to the first allowed ``sizes`` value (in bytes)
        that fits it, or truncate it to the largest size."""
        for size in sizes:
            if len(key) <= size:
                return key + b"\x00" * (size - len(key))
        return key[: sizes[-1]]

    def get_block_size(self) -> int:
        """Return block size in bytes. Override in subclass."""
        raise NotImplementedError("Subclass must implement get_block_size()")

    @staticmethod
    def _as_bytes(value, name: str) -> bytes:
        """Return ``value`` as bytes, rejecting str so hex is never guessed."""
        if isinstance(value, str):
            raise TypeError(f"{name} must be bytes, not str")
        return bytes(value)

    def _start_iv(self, iv: bytes, block_size: int, padding: str) -> bytes:
        """Return the IV for a chained mode, padded to one block if shorter."""
        if len(iv) != block_size:
            return self.pad(iv, block_size, padding)
        return iv

    def encrypt(
        self,
        plaintext: bytes,
        mode: str = "CBC",
        padding: str = "ISO 7816-4",
        iv: bytes = b"",
    ) -> bytes:
        """Encrypt ``plaintext`` bytes in ``mode`` (ECB, CBC, PCBC, CFB, OFB or
        CTR) and return the ciphertext bytes.

        ECB, CBC and PCBC pad the message per ``padding`` (always, even when
        block-aligned); CFB, OFB and CTR do not pad. ``iv`` is the IV or, for
        CTR, the initial counter block.
        """
        plaintext = self._as_bytes(plaintext, "plaintext")
        iv = self._as_bytes(iv, "iv")
        block_size = self.get_block_size()
        plaintext = self.pad_for_mode(plaintext, block_size, mode, padding)
        blocks = [
            plaintext[i : i + block_size] for i in range(0, len(plaintext), block_size)
        ]
        if mode != "ECB":
            iv = self._start_iv(iv, block_size, padding)

        result = bytearray()
        match mode:
            case "ECB":
                for block in blocks:
                    result.extend(self.encrypt_block(block))
            case "CBC":
                for block in blocks:
                    iv = self.encrypt_block(self.bitwise_xor_bytes(block, iv))
                    result.extend(iv)
            case "PCBC":
                for block in blocks:
                    encrypted = self.encrypt_block(self.bitwise_xor_bytes(block, iv))
                    iv = self.bitwise_xor_bytes(block, encrypted)
                    result.extend(encrypted)
            case "CFB":
                for block in blocks:
                    iv = self.bitwise_xor_bytes(self.encrypt_block(iv), block)
                    result.extend(iv)
            case "OFB":
                for block in blocks:
                    iv = self.encrypt_block(iv)
                    result.extend(self.bitwise_xor_bytes(block, iv))
            case "CTR":
                counter = int.from_bytes(iv, "big")
                for block in blocks:
                    keystream = self.encrypt_block(counter.to_bytes(block_size, "big"))
                    counter += 1
                    result.extend(self.bitwise_xor_bytes(block, keystream))
        return bytes(result)

    def decrypt(
        self,
        ciphertext: bytes,
        mode: str = "CBC",
        padding: str = "ISO 7816-4",
        iv: bytes = b"",
    ) -> bytes:
        """Decrypt ``ciphertext`` bytes in ``mode`` and return the plaintext.

        Mirrors :meth:`encrypt`: padding is removed for ECB, CBC and PCBC and
        malformed padding raises ``ValueError``; CFB, OFB and CTR are unpadded.
        """
        ciphertext = self._as_bytes(ciphertext, "ciphertext")
        iv = self._as_bytes(iv, "iv")
        block_size = self.get_block_size()
        if self.mode_needs_padding(mode) and len(ciphertext) % block_size:
            raise ValueError(
                f"{mode} ciphertext must be a multiple of {block_size} bytes"
            )
        blocks = [
            ciphertext[i : i + block_size]
            for i in range(0, len(ciphertext), block_size)
        ]
        if mode != "ECB":
            iv = self._start_iv(iv, block_size, padding)

        result = bytearray()
        match mode:
            case "ECB":
                for block in blocks:
                    result.extend(self.decrypt_block(block))
            case "CBC":
                for block in blocks:
                    result.extend(self.bitwise_xor_bytes(self.decrypt_block(block), iv))
                    iv = block
            case "PCBC":
                for block in blocks:
                    decrypted = self.bitwise_xor_bytes(self.decrypt_block(block), iv)
                    iv = self.bitwise_xor_bytes(block, decrypted)
                    result.extend(decrypted)
            case "CFB":
                for block in blocks:
                    result.extend(self.bitwise_xor_bytes(self.encrypt_block(iv), block))
                    iv = block
            case "OFB":
                for block in blocks:
                    iv = self.encrypt_block(iv)
                    result.extend(self.bitwise_xor_bytes(block, iv))
            case "CTR":
                counter = int.from_bytes(iv, "big")
                for block in blocks:
                    keystream = self.encrypt_block(counter.to_bytes(block_size, "big"))
                    counter += 1
                    result.extend(self.bitwise_xor_bytes(block, keystream))
        return self.unpad_for_mode(bytes(result), block_size, mode, padding)
