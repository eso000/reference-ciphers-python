"""Smoke test: every cipher reproduces its canonical single-block vector."""

from AES import AES
from Blowfish import Blowfish
from DES import DES, TripleDES
from Serpent import Serpent
from Twofish import Twofish

passed = True

c = DES()
c.generate_keys("AABB09182736CCDD")
cipher = c.encrypt_block(bytes.fromhex("123456ABCD132536")).hex()
if cipher != 'c0b7a8d05f3a829c':
    passed = False
    print("DES failed to encrypt")
if c.decrypt_block(bytes.fromhex(cipher)).hex() != "123456abcd132536":
    passed = False
    print("DES failed to decrypt")

c = TripleDES()
c.generate_keys("AABB09182736CCDD123456ABCD132536c0b7a8d05f3a829c")
cipher = c.encrypt_block(bytes.fromhex("123456ABCD132536")).hex()
if cipher != 'e6803bea92016d52':
    passed = False
    print("3DES failed to encrypt")
if c.decrypt_block(bytes.fromhex(cipher)).hex() != "123456abcd132536":
    passed = False
    print("3DES failed to decrypt")

c = Blowfish()
c.generate_keys("AABB09182736CCDD")
cipher = c.encrypt_block(bytes.fromhex("123456ABCD132536")).hex()
if cipher != 'c8fdcaea64fa2c82':
    passed = False
    print("Blowfish failed to encrypt")
if c.decrypt_block(bytes.fromhex(cipher)).hex() != "123456abcd132536":
    passed = False
    print("Blowfish failed to decrypt")

c = AES()
c.generate_keys("5468617473206d79204b756e672046755468617473206d79204b756e67204675")
cipher = c.encrypt_block(bytes.fromhex("74b57f06d9d78c2aec14559a74cf973c")).hex()
if cipher != '149da0c3e62301b5c725ebb8aa991d3c':
    passed = False
    print("AES failed to encrypt")
if c.decrypt_block(bytes.fromhex(cipher)).hex() != "74b57f06d9d78c2aec14559a74cf973c":
    passed = False
    print("AES failed to decrypt")

c = Serpent()
c.generate_keys("8000000000000000000000000000000000000000000000000000000000000000")
cipher = c.encrypt_block(bytes.fromhex("00000000000000000000000000000000")).hex()
if cipher != 'a223aa1288463c0e2be38ebd825616c0':
    passed = False
    print("Serpent failed to encrypt")
if c.decrypt_block(bytes.fromhex(cipher)).hex() != "00000000000000000000000000000000":
    passed = False
    print("Serpent failed to decrypt")

c = Twofish()
c.generate_keys("5468617473206d79204b756e672046755468617473206d79204b756e67204675")
cipher = c.encrypt_block(bytes.fromhex("74b57f06d9d78c2aec14559a74cf973c")).hex()
if cipher != '21c5b005fa127a864c58217b2dd2b703':
    passed = False
    print("Twofish failed to encrypt")
if c.decrypt_block(bytes.fromhex(cipher)).hex() != "74b57f06d9d78c2aec14559a74cf973c":
    passed = False
    print("Twofish failed to decrypt")

if passed:
    print("All passed")
