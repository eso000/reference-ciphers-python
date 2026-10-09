"""Command-line front end for the reference cipher implementations.

Encrypt and decrypt whole messages with any bundled cipher, or print the
supported ciphers, modes and padding schemes.

This is a thin wrapper over the same bytes-only API a Python user gets. It adds
no key derivation and no authentication, so it is an educational tool rather
than a safe way to protect real secrets.
"""

from __future__ import annotations

import argparse
import os
import sys
from typing import Dict, Optional, Sequence, Tuple, Type

from . import __version__
from .AES import AES
from .Blowfish import Blowfish
from .DES import DES, TripleDES
from .Serpent import Serpent
from .Twofish import Twofish
from .encryption_base import EncryptionBase

MODES = ("ECB", "CBC", "PCBC", "CFB", "OFB", "CTR")
PADDINGS = ("PKCS", "ANSI X9.23", "ISO 7816-4", "TBC", "0")

SECURITY_NOTICE = (
    "Reference/education tool: no key derivation, no authentication (no "
    "MAC/AEAD) and no constant-time guarantees. Do not use it to protect real "
    "secrets."
)

# Public cipher name -> class, plus display metadata for ``refciphers info``.
CIPHER_TABLE: Tuple[Tuple[str, Type[EncryptionBase], str, str], ...] = (
    ("aes", AES, "16, 24, 32", "FIPS-197"),
    ("des", DES, "8", "FIPS 46-3"),
    ("3des", TripleDES, "24", "SP 800-67 (EDE)"),
    ("blowfish", Blowfish, "4-56", "Schneier, 1993"),
    ("twofish", Twofish, "16, 24, 32", "AES submission"),
    ("serpent", Serpent, "16, 24, 32", "NESSIE finalist"),
)

CIPHER_CLASSES: Dict[str, Type[EncryptionBase]] = {
    name: cls for name, cls, _keys, _source in CIPHER_TABLE
}
# Convenience alias so ``--cipher tripledes`` works as well as ``--cipher 3des``.
CIPHER_CLASSES["tripledes"] = TripleDES


def _parse_hex(value: str, what: str) -> bytes:
    """Parse a hex string, tolerating spaces, colons and a ``0x`` prefix."""
    cleaned = value.strip().replace(":", "").replace(" ", "")
    if cleaned[:2].lower() == "0x":
        cleaned = cleaned[2:]
    if not cleaned:
        raise ValueError(f"{what} is empty")
    if len(cleaned) % 2:
        raise ValueError(f"{what} must have an even number of hex digits")
    try:
        return bytes.fromhex(cleaned)
    except ValueError as exc:
        raise ValueError(f"{what} is not valid hex: {value!r}") from exc


def _read_raw(path: Optional[str]) -> bytes:
    """Read raw bytes from ``path``, or all of stdin when path is None/-."""
    if path in (None, "-"):
        return sys.stdin.buffer.read()
    with open(path, "rb") as handle:
        return handle.read()


def _write_output(path: Optional[str], data: bytes, fmt: str) -> None:
    """Write ``data`` to ``path`` (stdout when None/-) as raw or hex bytes."""
    payload = (data.hex() + "\n").encode("ascii") if fmt == "hex" else data
    if path in (None, "-"):
        sys.stdout.buffer.write(payload)
        sys.stdout.buffer.flush()
        return
    with open(path, "wb") as handle:
        handle.write(payload)


def _load_key(args: argparse.Namespace) -> bytes:
    """Return the key from ``--key`` (hex) or ``--key-file`` (raw bytes)."""
    if args.key and args.key_file:
        raise ValueError("give either --key or --key-file, not both")
    if args.key_file:
        return _read_raw(args.key_file)
    if args.key:
        return _parse_hex(args.key, "key")
    raise ValueError("a key is required (--key or --key-file)")


def _load_iv(args: argparse.Namespace, cipher: EncryptionBase, encrypt: bool) -> bytes:
    """Resolve the IV: none for ECB, random for encryption, hex otherwise."""
    if args.mode == "ECB":
        if args.iv:
            raise ValueError("ECB mode does not use an IV")
        return b""
    iv_arg = args.iv
    if iv_arg is None:
        if not encrypt:
            raise ValueError("decrypt needs --iv (the IV used to encrypt)")
        iv_arg = "random"
    if iv_arg.lower() == "random":
        if not encrypt:
            raise ValueError("--iv random is only valid when encrypting")
        iv = os.urandom(cipher.block_size)
        print(f"iv={iv.hex()}", file=sys.stderr)
        return iv
    return _parse_hex(iv_arg, "iv")


def _read_input(args: argparse.Namespace, decode_hex: bool) -> bytes:
    """Read stdin/file; optionally decode it from hex (ciphertext input)."""
    raw = _read_raw(args.input)
    if not decode_hex:
        return raw
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError as exc:
        raise ValueError("hex input contains non-ASCII bytes") from exc
    return _parse_hex(text, "input")


def cmd_encrypt(args: argparse.Namespace) -> int:
    """Encrypt stdin/file, writing raw or hex ciphertext to stdout/file."""
    cipher = CIPHER_CLASSES[args.cipher]()
    cipher.generate_keys(_load_key(args))
    iv = _load_iv(args, cipher, encrypt=True)
    plaintext = _read_input(args, decode_hex=False)
    ciphertext = cipher.encrypt(plaintext, mode=args.mode, padding=args.padding, iv=iv)
    _write_output(args.output, ciphertext, args.format)
    return 0


def cmd_decrypt(args: argparse.Namespace) -> int:
    """Decrypt stdin/file ciphertext to raw plaintext."""
    cipher = CIPHER_CLASSES[args.cipher]()
    cipher.generate_keys(_load_key(args))
    iv = _load_iv(args, cipher, encrypt=False)
    ciphertext = _read_input(args, decode_hex=args.format == "hex")
    plaintext = cipher.decrypt(ciphertext, mode=args.mode, padding=args.padding, iv=iv)
    _write_output(args.output, plaintext, "raw")
    return 0


def cmd_info(_args: argparse.Namespace) -> int:
    """Print the supported ciphers, modes and padding schemes."""
    print("Ciphers")
    for name, cls, keys, source in CIPHER_TABLE:
        print(f"  {name:<9} block {cls.block_size:>2} B   key {keys:<11} {source}")
    print()
    print("Modes   :", ", ".join(MODES))
    print("Padding :", ", ".join(PADDINGS), "(empty string means no padding)")
    print()
    print(SECURITY_NOTICE)
    return 0


def _build_parser() -> argparse.ArgumentParser:
    """Build the argument parser with its encrypt/decrypt/info subcommands."""
    parser = argparse.ArgumentParser(
        prog="refciphers",
        description="Encrypt and decrypt messages with the bundled reference "
        "block ciphers.",
        epilog=SECURITY_NOTICE,
    )
    parser.add_argument(
        "--version", action="version", version=f"%(prog)s {__version__}"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    for name, handler in (("encrypt", cmd_encrypt), ("decrypt", cmd_decrypt)):
        sub = subparsers.add_parser(
            name, help=f"{name} a message", description=SECURITY_NOTICE
        )
        sub.add_argument(
            "--cipher", required=True, choices=sorted(CIPHER_CLASSES), help="cipher"
        )
        sub.add_argument("--key", help="key as hex")
        sub.add_argument(
            "--key-file", dest="key_file", help="file containing the raw key bytes"
        )
        sub.add_argument("--mode", default="CBC", choices=MODES, help="block mode")
        sub.add_argument(
            "--padding",
            default="ISO 7816-4",
            choices=("",) + PADDINGS,
            help="padding scheme (default: ISO 7816-4)",
        )
        sub.add_argument("--iv", help="IV as hex, or 'random' when encrypting")
        sub.add_argument("-i", "--input", help="input file (default: stdin)")
        sub.add_argument("-o", "--output", help="output file (default: stdout)")
        sub.add_argument(
            "--format",
            default="raw",
            choices=("raw", "hex"),
            help="ciphertext encoding, for output (encrypt) or input (decrypt)",
        )
        sub.set_defaults(func=handler)

    info = subparsers.add_parser(
        "info", help="list supported ciphers, modes and padding"
    )
    info.set_defaults(func=cmd_info)
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Run the command line; return the process exit code."""
    parser = _build_parser()
    args = parser.parse_args(argv)
    func = getattr(args, "func", None)
    if func is None:  # pragma: no cover - argparse requires a subcommand
        parser.print_help(sys.stderr)
        return 2
    try:
        return int(func(args))
    except (ValueError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
