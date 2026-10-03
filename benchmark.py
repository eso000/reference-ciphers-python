"""ECB/CBC throughput benchmark for all block ciphers in the repo."""

import time

from src.AES import AES
from src.Blowfish import Blowfish
from src.DES import DES, TripleDES
from src.Serpent import Serpent
from src.Twofish import Twofish

CIPHERS = [
    (DES(), "0011223344556677"),
    (TripleDES(), "00112233445566778899aabbccddeeff0011223344556677"),
    (Blowfish(), "00112233445566778899aabbccddeeff"),
    (AES(), "000102030405060708090a0b0c0d0e0f"),
    (Serpent(), "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"),
    (Twofish(), "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"),
]

B_SIZE = 4000
MSG = bytes(B_SIZE)

for obj, key in CIPHERS:
    obj.generate_keys(bytes.fromhex(key))

for i in range(4):
    print("ECB:")
    for obj, _ in CIPHERS:
        print(type(obj), end="\t\t")
        start_time = time.time()
        obj.encrypt(MSG, mode="ECB")
        print(B_SIZE / 1000 / (time.time() - start_time))

    print("CBC:")
    for obj, _ in CIPHERS:
        print(type(obj), end="\t\t")
        start_time = time.time()
        obj.encrypt(MSG, mode="CBC", iv=bytes(obj.block_size))
        print(B_SIZE / 1000 / (time.time() - start_time))
