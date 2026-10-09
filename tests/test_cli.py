"""Tests for the ``refciphers`` command-line interface.

Walks encrypt/decrypt round trips (raw and hex ciphertext), the random-IV
path, ``info``, and the failure modes (missing key, bad hex, ECB with an IV,
decrypt without an IV). Runs the CLI like a user would, through file
arguments, so every subcommand is exercised end to end.
"""

import contextlib
import io
import os
import tempfile
import unittest

from refciphers.cli import main

KEY = "000102030405060708090a0b0c0d0e0f"
IV = "101112131415161718191a1b1c1d1e1f"


# pylint: disable=too-few-public-methods
class _FakeStdout:
    """Minimal stand-in for sys.stdout with a binary buffer."""

    def __init__(self):
        self.buffer = io.BytesIO()


class CliTestCase(unittest.TestCase):
    """Encrypt/decrypt round trips through the CLI in both encodings."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()  # pylint: disable=consider-using-with
        self.addCleanup(self.tmp.cleanup)

    def path(self, name):
        """Return the absolute path of a temp-file name."""
        return os.path.join(self.tmp.name, name)

    def write(self, name, data):
        """Write ``data`` to a fresh temp file."""
        with open(self.path(name), "wb") as handle:
            handle.write(data)

    def read(self, name):
        """Read and return a temp file's contents."""
        with open(self.path(name), "rb") as handle:
            return handle.read()

    def test_round_trip_raw(self):
        """Binary plaintext survives encrypt+decrypt with a raw ciphertext."""
        plaintext = b"attack at dawn \x00\xff binary \xc3\xa9"
        self.write("in.bin", plaintext)
        code = main(
            [
                "encrypt",
                "--cipher",
                "aes",
                "--key",
                KEY,
                "--mode",
                "CBC",
                "--iv",
                IV,
                "-i",
                self.path("in.bin"),
                "-o",
                self.path("ct.bin"),
            ]
        )
        self.assertEqual(code, 0)
        code = main(
            [
                "decrypt",
                "--cipher",
                "aes",
                "--key",
                KEY,
                "--mode",
                "CBC",
                "--iv",
                IV,
                "-i",
                self.path("ct.bin"),
                "-o",
                self.path("out.bin"),
            ]
        )
        self.assertEqual(code, 0)
        self.assertEqual(self.read("out.bin"), plaintext)

    def test_round_trip_hex(self):
        """Hex ciphertext on disk decrypts back to the plaintext."""
        plaintext = b"hex mode round trip"
        self.write("in.bin", plaintext)
        code = main(
            [
                "encrypt",
                "--cipher",
                "aes",
                "--key",
                KEY,
                "--mode",
                "CFB",
                "--iv",
                IV,
                "--format",
                "hex",
                "-i",
                self.path("in.bin"),
                "-o",
                self.path("ct.hex"),
            ]
        )
        self.assertEqual(code, 0)
        hexified = self.read("ct.hex").decode("ascii").strip()
        self.assertRegex(hexified, r"^[0-9a-f]+$")
        code = main(
            [
                "decrypt",
                "--cipher",
                "aes",
                "--key",
                KEY,
                "--mode",
                "CFB",
                "--iv",
                IV,
                "--format",
                "hex",
                "-i",
                self.path("ct.hex"),
                "-o",
                self.path("out.bin"),
            ]
        )
        self.assertEqual(code, 0)
        self.assertEqual(self.read("out.bin"), plaintext)

    def test_stdout_round_trip(self):
        """With no -o the ciphertext goes to stdout as raw bytes."""
        plaintext = b"to stdout"
        self.write("in.bin", plaintext)
        stdout = _FakeStdout()
        with contextlib.redirect_stdout(stdout):
            code = main(
                [
                    "encrypt",
                    "--cipher",
                    "twofish",
                    "--key",
                    "00" * 16,
                    "--iv",
                    IV,
                    "-i",
                    self.path("in.bin"),
                ]
            )
        self.assertEqual(code, 0)
        ciphertext = stdout.buffer.getvalue()
        self.write("ct.bin", ciphertext)
        code = main(
            [
                "decrypt",
                "--cipher",
                "twofish",
                "--key",
                "00" * 16,
                "--iv",
                IV,
                "-i",
                self.path("ct.bin"),
                "-o",
                self.path("out.bin"),
            ]
        )
        self.assertEqual(code, 0)
        self.assertEqual(self.read("out.bin"), plaintext)

    def test_random_iv_is_reported(self):
        """Encrypting without --iv generates one and prints it to stderr."""
        self.write("in.bin", b"random iv path")
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            code = main(
                [
                    "encrypt",
                    "--cipher",
                    "serpent",
                    "--key",
                    "11" * 32,
                    "-i",
                    self.path("in.bin"),
                    "-o",
                    self.path("ct.bin"),
                ]
            )
        self.assertEqual(code, 0)
        self.assertIn("iv=", stderr.getvalue())

    def test_info_lists_everything(self):
        """``info`` prints ciphers, modes and padding names."""
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            code = main(["info"])
        self.assertEqual(code, 0)
        text = stdout.getvalue()
        for name in ("aes", "serpent", "twofish"):
            self.assertIn(name, text)
        self.assertIn("PCBC", text)
        self.assertIn("ISO 7816-4", text)

    def test_missing_key_is_an_error(self):
        """A cipher with no key exits 1 with an error on stderr."""
        self.write("in.bin", b"x")
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            code = main(
                [
                    "encrypt",
                    "--cipher",
                    "aes",
                    "-i",
                    self.path("in.bin"),
                    "-o",
                    self.path("ct.bin"),
                ]
            )
        self.assertEqual(code, 1)
        self.assertIn("error:", stderr.getvalue())

    def test_invalid_hex_key_is_an_error(self):
        """Non-hexadecimal key bytes exit 1."""
        self.write("in.bin", b"x")
        code = main(
            [
                "encrypt",
                "--cipher",
                "aes",
                "--key",
                "zz",
                "--iv",
                IV,
                "-i",
                self.path("in.bin"),
                "-o",
                self.path("ct.bin"),
            ]
        )
        self.assertEqual(code, 1)

    def test_ecb_rejects_iv(self):
        """ECB mode with an explicit IV is rejected."""
        code = main(
            [
                "encrypt",
                "--cipher",
                "aes",
                "--key",
                KEY,
                "--mode",
                "ECB",
                "--iv",
                IV,
                "-i",
                self.path("in.bin"),
                "-o",
                self.path("ct.bin"),
            ]
        )
        self.assertEqual(code, 1)

    def test_decrypt_requires_iv(self):
        """CBC decryption without an IV exits 1."""
        self.write("ct.bin", b"16 bytes of ct!")
        code = main(
            [
                "decrypt",
                "--cipher",
                "aes",
                "--key",
                KEY,
                "--mode",
                "CBC",
                "-i",
                self.path("ct.bin"),
                "-o",
                self.path("out.bin"),
            ]
        )
        self.assertEqual(code, 1)


if __name__ == "__main__":
    unittest.main()
