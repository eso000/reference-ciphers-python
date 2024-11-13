from encryptionBase import *

class DES(encryptionBase):
	initialperm = [ 58, 50, 42, 34, 26, 18, 10, 2,
                60, 52, 44, 36, 28, 20, 12, 4,
                62, 54, 46, 38, 30, 22, 14, 6,
                64, 56, 48, 40, 32, 24, 16, 8,
                57, 49, 41, 33, 25, 17, 9, 1,
                59, 51, 43, 35, 27, 19, 11, 3,
                61, 53, 45, 37, 29, 21, 13, 5,
                63, 55, 47, 39, 31, 23, 15, 7 ]
	inverseperm = [ 40,	8,	48,	16,	56,	24,	64,	32,
				39,	7,	47,	15,	55,	23,	63,	31,
				38,	6,	46,	14,	54,	22,	62,	30,
				37,	5,	45,	13,	53,	21,	61,	29,
				36,	4,	44,	12,	52,	20,	60,	28,
				35,	3,	43,	11,	51,	19,	59,	27,
				34,	2,	42,	10,	50,	18,	58,	26,
				33,	1,	41,	9,	49,	17,	57,	25 ]
	ExpentionPerm = [ 32, 1, 2, 3, 4, 5,
										 4, 5, 6, 7, 8, 9, 
										 8, 9, 10, 11, 12, 13,
										12, 13, 14, 15, 16, 17,
                    16, 17, 18, 19, 20, 21,
                    20, 21, 22, 23, 24, 25, 
                    24, 25, 26, 27, 28, 29,
                    28, 29, 30, 31, 32, 1 ]
	SBoxes = [[14, 0, 4, 15, 13, 7, 1, 4, 2, 14, 15, 2, 11, 13, 8, 1, 3, 10, 10, 6, 6, 12, 12, 11, 5, 9, 9, 5, 0, 3, 7, 8, 4, 15, 1, 12, 14, 8, 8, 2, 13, 4, 6, 9, 2, 1, 11, 7, 15, 5, 12, 11, 9, 3, 7, 14, 3, 10, 10, 0, 5, 6, 0, 13],
						[15, 3, 1, 13, 8, 4, 14, 7, 6, 15, 11, 2, 3, 8, 4, 14, 9, 12, 7, 0, 2, 1, 13, 10, 12, 6, 0, 9, 5, 11, 10, 5, 0, 13, 14, 8, 7, 10, 11, 1, 10, 3, 4, 15, 13, 4, 1, 2, 5, 11, 8, 6, 12, 7, 6, 12, 9, 0, 3, 5, 2, 14, 15, 9],
						[10, 13, 0, 7, 9, 0, 14, 9, 6, 3, 3, 4, 15, 6, 5, 10, 1, 2, 13, 8, 12, 5, 7, 14, 11, 12, 4, 11, 2, 15, 8, 1, 13, 1, 6, 10, 4, 13, 9, 0, 8, 6, 15, 9, 3, 8, 0, 7, 11, 4, 1, 15, 2, 14, 12, 3, 5, 11, 10, 5, 14, 2, 7, 12],
						[7, 13, 13, 8, 14, 11, 3, 5, 0, 6, 6, 15, 9, 0, 10, 3, 1, 4, 2, 7, 8, 2, 5, 12, 11, 1, 12, 10, 4, 14, 15, 9, 10, 3, 6, 15, 9, 0, 0, 6, 12, 10, 11, 1, 7, 13, 13, 8, 15, 9, 1, 4, 3, 5, 14, 11, 5, 12, 2, 7, 8, 2, 4, 14],
						[2, 14, 12, 11, 4, 2, 1, 12, 7, 4, 10, 7, 11, 13, 6, 1, 8, 5, 5, 0, 3, 15, 15, 10, 13, 3, 0, 9, 14, 8, 9, 6, 4, 11, 2, 8, 1, 12, 11, 7, 10, 1, 13, 14, 7, 2, 8, 13, 15, 6, 9, 15, 12, 0, 5, 9, 6, 10, 3, 4, 0, 5, 14, 3],
						[12, 10, 1, 15, 10, 4, 15, 2, 9, 7, 2, 12, 6, 9, 8, 5, 0, 6, 13, 1, 3, 13, 4, 14, 14, 0, 7, 11, 5, 3, 11, 8, 9, 4, 14, 3, 15, 2, 5, 12, 2, 9, 8, 5, 12, 15, 3, 10, 7, 11, 0, 14, 4, 1, 10, 7, 1, 6, 13, 0, 11, 8, 6, 13],
						[4, 13, 11, 0, 2, 11, 14, 7, 15, 4, 0, 9, 8, 1, 13, 10, 3, 14, 12, 3, 9, 5, 7, 12, 5, 2, 10, 15, 6, 8, 1, 6, 1, 6, 4, 11, 11, 13, 13, 8, 12, 1, 3, 4, 7, 10, 14, 7, 10, 9, 15, 5, 6, 0, 8, 15, 0, 14, 5, 2, 9, 3, 2, 12],
						[13, 1, 2, 15, 8, 13, 4, 8, 6, 10, 15, 3, 11, 7, 1, 4, 10, 12, 9, 5, 3, 6, 14, 11, 5, 0, 0, 14, 12, 9, 7, 2, 7, 2, 11, 1, 4, 14, 1, 7, 9, 4, 12, 10, 14, 8, 2, 13, 0, 15, 6, 12, 10, 9, 13, 0, 15, 3, 3, 5, 5, 6, 8, 11]]


	keyperm1 =  [57, 49, 41, 33, 25, 17, 9,
        	1, 58, 50, 42, 34, 26, 18,
        	10, 2, 59, 51, 43, 35, 27,
        	19, 11, 3, 60, 52, 44, 36,
        	63, 55, 47, 39, 31, 23, 15,
        	7, 62, 54, 46, 38, 30, 22,
        	14, 6, 61, 53, 45, 37, 29,
        	21, 13, 5, 28, 20, 12, 4 ]
	keyperm2 = [14, 17, 11, 24, 1, 5,
            3, 28, 15, 6, 21, 10,
            23, 19, 12, 4, 26, 8,
            16, 7, 27, 20, 13, 2,
            41, 52, 31, 37, 47, 55,
            30, 40, 51, 45, 33, 48,
            44, 49, 39, 56, 34, 53,
            46, 42, 50, 36, 29, 32 ]
	PBox = [ 16,  7, 20, 21,
		 29, 12, 28, 17,
         1, 15, 23, 26,
         5, 18, 31, 10,
         2,  8, 24, 14,
         32, 27,  3,  9,
         19, 13, 30,  6,
         22, 11,  4, 25 ]

	Subkeys = []


	def generateKeys(self,key):
		if len(key) < 16:
			key = self.pad(key,16,'0')
		key = self.HexToBin(key)
		key = [key[i-1] for i in self.keyperm1]#self.permutate(key, self.keyperm1)
		leftKey = key[0:28]
		rightKey = key[28:56]
		Subkeys1 = []
		for i in range(16):
			if i + 1 in (1,2,9,16):
				shift = 1
			else:
				shift = 2
			leftKey = self.rotl(leftKey, shift)
			rightKey = self.rotl(rightKey, shift)
			Subkeys1.append(int(self.permutate(leftKey + rightKey, self.keyperm2),2))
		self.Subkeys = Subkeys1

	def F(self,plt, subkey):
		plaintext = "".join([plt[31]]+[plt[0:5]]+ [plt[4*i-1:4*i+5] for i in range(1,7)]+[plt[27:32]]+[plt[0]])
		plaintext = bin(int(plaintext,2)^ subkey)[2:].zfill(48)
		sbox_str = "".join([bin(self.SBoxes[j][int(str(plaintext[j * 6:j * 6 + 6]),2)])[2:].zfill(4)
			for j in range(0, 8)])
		return ''.join([sbox_str[i-1] for i in self.PBox])

	def encrypt_block(self,plaintext):
		plaintext = self.HexToBin(plaintext)
		plaintext = "".join([ plaintext[i-1] for i in self.initialperm])
		left = plaintext[0:32]
		right = plaintext[32:64] 
		for i in range(16):
			new_left = right
			right = self.F(right, self.Subkeys[i])
			new_right = bin(int(left,2)^int(right,2))[2:].zfill(32)

			left = new_left
			right = new_right
		x = right + left
		return self.BinToHex("".join([x[i-1] for i in self.inverseperm]))

	def decrypt_block(self,plaintext):
		plaintext = self.HexToBin(plaintext)
		plaintext = self.permutate(plaintext, self.initialperm)
		left = plaintext[0:32]
		right = plaintext[32:64] 
		for i in range(16):
			new_left = right
			right = self.F(right, self.Subkeys[15-i])
			new_right = bin(int(left,2)^int(right,2))[2:].zfill(32)
			
			left = new_left
			right = new_right
		return self.BinToHex(self.permutate(right + left, self.inverseperm))

	def encrypt(self, plaintext,mode = 'CBC',padding = 'bit',iv = ''):
		return self.encrypt_mode(16,plaintext, mode, padding, iv)

	def decrypt(self, plaintext,mode = 'CBC',padding = 'bit',iv = ''):
		return self.decrypt_mode(16,plaintext, mode, padding, iv)


class TrippleDES(encryptionBase):
	des1 = DES()
	des2 = DES()
	des3 = DES()

	def encrypt_block(self,plt):
		plt = self.des1.encrypt_block(plt)
		plt = self.des2.decrypt_block(plt)
		return self.des3.encrypt_block(plt)

	def decrypt_block(self,plt):
		plt = self.des3.decrypt_block(plt)
		plt = self.des2.encrypt_block(plt)
		return self.des1.decrypt_block(plt)


	def generateKeys(self,key):
		self.des1.generateKeys(key[0:16])
		self.des2.generateKeys(key[16:32])
		self.des3.generateKeys(key[32:48])

	def encrypt(self, plaintext,mode = 'CBC',padding = 'bit',iv = ''):
		plaintext = self.des1.encrypt(plaintext, mode, padding, iv)
		plaintext = self.des2.decrypt(plaintext, mode, padding, iv)
		return self.des3.encrypt(plaintext, mode, padding, iv)

	def decrypt(self, plaintext,mode = 'CBC',padding = 'bit',iv = ''):
		plaintext = self.des3.decrypt(plaintext, mode, padding, iv)
		plaintext = self.des2.encrypt(plaintext, mode, padding, iv)
		return self.des1.decrypt(plaintext, mode, padding, iv)
