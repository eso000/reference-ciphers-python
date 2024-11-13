from encryptionBase import *
from AES import *
from Serpent import *
from Blowfish import *
from DES import *
from Twofish import *
import time


passed = True

c = DES()
c.generateKeys("AABB09182736CCDD")
cipher = c.encrypt_block("123456ABCD132536")
if cipher != 'c0b7a8d05f3a829c':
	passed = False
	print("DES failed to encrypt")
if c.decrypt_block(cipher) != "123456abcd132536":
	passed = False
	print("DES failed to decrypt")


c = TrippleDES()
c.generateKeys("AABB09182736CCDD123456ABCD132536c0b7a8d05f3a829c")
cipher = c.encrypt_block("123456ABCD132536")
if cipher != 'e6803bea92016d52':
	print(cipher)
	passed = False
	print("3DES failed to encrypt")
if c.decrypt_block(cipher) != "123456abcd132536":
	passed = False
	print("3DES failed to decrypt")



c = Blowfish()
c.generateKeys("AABB09182736CCDD")
cipher = c.encrypt_block("123456ABCD132536")
if cipher != 'c8fdcaea64fa2c82':
	passed = False
	print("Blowfish failed to encrypt")
if c.decrypt_block(cipher) != "123456abcd132536":
	passed = False
	print("Blowfish failed to decrypt")

c = AES()
c.generateKeys("5468617473206d79204b756e672046755468617473206d79204b756e67204675")
cipher = c.encrypt_block("74b57f06d9d78c2aec14559a74cf973c")
if cipher != '149da0c3e62301b5c725ebb8aa991d3c':
	passed = False
	print("AES failed to encrypt")
if c.decrypt_block(cipher) != "74b57f06d9d78c2aec14559a74cf973c":
	passed = False
	print("AES failed to decrypt")


c = Serpent()
c.generateKeys("5468617473206d79204b756e672046755468617473206d79204b756e67204675")
cipher = c.encrypt_block("74b57f06d9d78c2aec14559a74cf973c")
if cipher != 'ae6170a46ed549b9f97a17f1cc8ac2f1':
	passed = False
	print("Serpent failed to encrypt")
if c.decrypt_block(cipher) != "74b57f06d9d78c2aec14559a74cf973c":
	passed = False
	print("Serpent failed to decrypt")

c = Twofish()
c.generateKeys("5468617473206d79204b756e672046755468617473206d79204b756e67204675")
cipher = c.encrypt_block("74b57f06d9d78c2aec14559a74cf973c")
if cipher != '21c5b005fa127a864c58217b2dd2b703':
	passed = False
	print("Twofish failed to encrypt")
if c.decrypt_block(cipher) != "74b57f06d9d78c2aec14559a74cf973c":
	passed = False
	print("Twofish failed to decrypt")


if passed:
	print("All passed")
