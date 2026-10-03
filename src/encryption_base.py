"""Shared arithmetic and padding helpers for the teaching ciphers."""

from typing import List


class EncryptionBase:
    """Base class supplying XOR, bit permutation, rotation and the
    block-mode scaffolding shared by the ciphers."""

    block_size: int  # block size in bytes; hard-coded by each cipher

    @staticmethod
    def bitwise_xor_bytes(data1: bytes, data2: bytes) -> bytes:
        """XOR two equal-length byte sequences."""
        min_len = min(len(data1), len(data2))
        return bytes(data1[i] ^ data2[i] for i in range(min_len))

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
    def rotl(val: int, shifts: int, width: int) -> int:
        """Rotate ``val`` left by ``shifts`` bits within ``width`` bits."""
        shifts %= width
        return ((val << shifts) | (val >> (width - shifts))) % (1 << width)

    @staticmethod
    def rotr(val: int, shifts: int, width: int) -> int:
        """Rotate ``val`` right by ``shifts`` bits within ``width`` bits."""
        shifts %= width
        return ((val >> shifts) | (val << (width - shifts))) % (1 << width)

    def encrypt_block(self, plaintext: bytes) -> bytes:
        """Placeholder: single-block encryption, overridden by each cipher."""
        return plaintext

    def decrypt_block(self, ciphertext: bytes) -> bytes:
        """Placeholder: single-block decryption, overridden by each cipher."""
        return ciphertext

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

    @staticmethod
    def _as_bytes(value, name: str) -> bytes:
        """Return ``value`` as bytes, rejecting str so hex is never guessed."""
        if isinstance(value, str):
            raise TypeError(f"{name} must be bytes, not str")
        return bytes(value)

    @classmethod
    def _checked_key(cls, key: bytes, sizes: tuple, label: str) -> bytes:
        """Return ``key`` as bytes, requiring its length to be in ``sizes``."""
        key = cls._as_bytes(key, "key")
        if len(key) not in sizes:
            allowed = ", ".join(str(n) for n in sizes[:-1])
            allowed = f"{allowed} or {sizes[-1]}" if allowed else str(sizes[-1])
            raise ValueError(f"{label} key must be {allowed} bytes, got {len(key)}")
        return key

    def _checked_block(self, data: bytes) -> bytes:
        """Return ``data`` as bytes, requiring exactly one cipher block."""
        data = self._as_bytes(data, "block")
        if len(data) != self.block_size:
            raise ValueError(f"block must be {self.block_size} bytes, got {len(data)}")
        return data

    @staticmethod
    def _check_iv(iv: bytes, block_size: int, mode: str) -> None:
        """Require a ``block_size``-byte IV for chained modes and none for ECB."""
        if mode == "ECB":
            if iv:
                raise ValueError("ECB mode does not use an IV")
        elif len(iv) != block_size:
            raise ValueError(f"{mode} needs a {block_size}-byte IV, got {len(iv)}")

    def _mode_ecb(self, blocks: List[bytes], _iv: bytes, decrypt: bool) -> bytes:
        """ECB: every block is enciphered on its own, with no chaining."""
        block_fn = self.decrypt_block if decrypt else self.encrypt_block
        result = bytearray()
        for block in blocks:
            result.extend(block_fn(block))
        return bytes(result)

    def _mode_cbc(self, blocks: List[bytes], iv: bytes, decrypt: bool) -> bytes:
        """CBC: XOR with the previous ciphertext block, then encipher.

        Encrypting feeds the ciphertext forward; decrypting feeds the input
        block forward, because that input *is* the ciphertext.
        """
        result = bytearray()
        if decrypt:
            for block in blocks:
                result.extend(self.bitwise_xor_bytes(self.decrypt_block(block), iv))
                iv = block
            return bytes(result)
        for block in blocks:
            iv = self.encrypt_block(self.bitwise_xor_bytes(block, iv))
            result.extend(iv)
        return bytes(result)

    def _mode_pcbc(self, blocks: List[bytes], iv: bytes, decrypt: bool) -> bytes:
        """PCBC: like CBC, but the chain is XORed with the plaintext too."""
        result = bytearray()
        if decrypt:
            for block in blocks:
                decrypted = self.bitwise_xor_bytes(self.decrypt_block(block), iv)
                iv = self.bitwise_xor_bytes(block, decrypted)
                result.extend(decrypted)
            return bytes(result)
        for block in blocks:
            encrypted = self.encrypt_block(self.bitwise_xor_bytes(block, iv))
            iv = self.bitwise_xor_bytes(block, encrypted)
            result.extend(encrypted)
        return bytes(result)

    def _mode_cfb(self, blocks: List[bytes], iv: bytes, decrypt: bool) -> bytes:
        """CFB: turn the cipher into a keystream generator and XOR.

        Both directions run the cipher on the IV only. The chaining value is
        the ciphertext, which is this run's output when encrypting and this
        run's input when decrypting.
        """
        result = bytearray()
        for block in blocks:
            out = self.bitwise_xor_bytes(self.encrypt_block(iv), block)
            result.extend(out)
            iv = block if decrypt else out
        return bytes(result)

    def _mode_ofb(self, blocks: List[bytes], iv: bytes) -> bytes:
        """OFB: XOR with a keystream the cipher generates from the IV alone.

        No ciphertext is ever fed back, so one implementation serves both
        directions.
        """
        result = bytearray()
        for block in blocks:
            iv = self.encrypt_block(iv)
            result.extend(self.bitwise_xor_bytes(block, iv))
        return bytes(result)

    def _mode_ctr(self, blocks: List[bytes], iv: bytes) -> bytes:
        """CTR: XOR with the cipher applied to a big-endian counter block.

        Only the counter is fed forward, so one implementation serves both
        directions.
        """
        result = bytearray()
        counter = int.from_bytes(iv, "big")
        for block in blocks:
            keystream = self.encrypt_block(counter.to_bytes(self.block_size, "big"))
            counter += 1
            result.extend(self.bitwise_xor_bytes(block, keystream))
        return bytes(result)

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
        block-aligned); CFB, OFB and CTR do not pad. Every mode except ECB
        requires an ``iv`` of exactly one block (for CTR, the initial counter
        block); ECB rejects an IV.
        """
        plaintext = self._as_bytes(plaintext, "plaintext")
        iv = self._as_bytes(iv, "iv")
        block_size = self.block_size
        plaintext = self.pad_for_mode(plaintext, block_size, mode, padding)
        blocks = [
            plaintext[i : i + block_size] for i in range(0, len(plaintext), block_size)
        ]
        self._check_iv(iv, block_size, mode)

        match mode:
            case "ECB":
                return self._mode_ecb(blocks, iv, decrypt=False)
            case "CBC":
                return self._mode_cbc(blocks, iv, decrypt=False)
            case "PCBC":
                return self._mode_pcbc(blocks, iv, decrypt=False)
            case "CFB":
                return self._mode_cfb(blocks, iv, decrypt=False)
            case "OFB":
                return self._mode_ofb(blocks, iv)
            case "CTR":
                return self._mode_ctr(blocks, iv)
            case _:
                raise ValueError(f"Unknown mode '{mode}'")

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
        block_size = self.block_size
        if self.mode_needs_padding(mode) and len(ciphertext) % block_size:
            raise ValueError(
                f"{mode} ciphertext must be a multiple of {block_size} bytes"
            )
        blocks = [
            ciphertext[i : i + block_size]
            for i in range(0, len(ciphertext), block_size)
        ]
        self._check_iv(iv, block_size, mode)

        match mode:
            case "ECB":
                result = self._mode_ecb(blocks, iv, decrypt=True)
            case "CBC":
                result = self._mode_cbc(blocks, iv, decrypt=True)
            case "PCBC":
                result = self._mode_pcbc(blocks, iv, decrypt=True)
            case "CFB":
                result = self._mode_cfb(blocks, iv, decrypt=True)
            case "OFB":
                result = self._mode_ofb(blocks, iv)
            case "CTR":
                result = self._mode_ctr(blocks, iv)
            case _:
                raise ValueError(f"Unknown mode '{mode}'")
        return self.unpad_for_mode(result, block_size, mode, padding)
