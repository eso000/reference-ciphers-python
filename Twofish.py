from encryptionBase import *

class Twofish(encryptionBase):

	def rotl(self, a,s,n):
		return (((a>>s)|(a<< n-s))%(2**n))
	
	def rotr(self, a,s,n):
		return (((a<<s)|(a>> n-s))%(2**n))


	RS =[[1,164,85,135,90,88,219,158],
		 [164,86,130,243,30,198,104,229],
		 [2,161,252,193,71,174,61,25],
		 [164,85,135,90,88,219,158,3]]
	MDS = [[1,239,91,91],
		   [91,239,239,1],
		   [239,91,1,239],
		   [239,1,239,91]]
	MDS_Table = [[0,239,183,88,7,232,176,95,14,225,185,86,9,230,190,81,28,243,171,68,27,244,172,67,18,253,165,74,21,250,162,77,56,215,143,96,63,208,136,103,54,217,129,110,49,222,134,105,36,203,147,124,35,204,148,123,42,197,157,114,45,194,154,117,112,159,199,40,119,152,192,47,126,145,201,38,121,150,206,33,108,131,219,52,107,132,220,51,98,141,213,58,101,138,210,61,72,167,255,16,79,160,248,23,70,169,241,30,65,174,246,25,84,187,227,12,83,188,228,11,90,181,237,2,93,178,234,5,224,15,87,184,231,8,80,191,238,1,89,182,233,6,94,177,252,19,75,164,251,20,76,163,242,29,69,170,245,26,66,173,216,55,111,128,223,48,104,135,214,57,97,142,209,62,102,137,196,43,115,156,195,44,116,155,202,37,125,146,205,34,122,149,144,127,39,200,151,120,32,207,158,113,41,198,153,118,46,193,140,99,59,212,139,100,60,211,130,109,53,218,133,106,50,221,168,71,31,240,175,64,24,247,166,73,17,254,161,78,22,249,180,91,3,236,179,92,4,235,186,85,13,226,189,82,10,229],
				 [0,91,182,237,5,94,179,232,10,81,188,231,15,84,185,226,20,79,162,249,17,74,167,252,30,69,168,243,27,64,173,246,40,115,158,197,45,118,155,192,34,121,148,207,39,124,145,202,60,103,138,209,57,98,143,212,54,109,128,219,51,104,133,222,80,11,230,189,85,14,227,184,90,1,236,183,95,4,233,178,68,31,242,169,65,26,247,172,78,21,248,163,75,16,253,166,120,35,206,149,125,38,203,144,114,41,196,159,119,44,193,154,108,55,218,129,105,50,223,132,102,61,208,139,99,56,213,142,160,251,22,77,165,254,19,72,170,241,28,71,175,244,25,66,180,239,2,89,177,234,7,92,190,229,8,83,187,224,13,86,136,211,62,101,141,214,59,96,130,217,52,111,135,220,49,106,156,199,42,113,153,194,47,116,150,205,32,123,147,200,37,126,240,171,70,29,245,174,67,24,250,161,76,23,255,164,73,18,228,191,82,9,225,186,87,12,238,181,88,3,235,176,93,6,216,131,110,53,221,134,107,48,210,137,100,63,215,140,97,58,204,151,122,33,201,146,127,36,198,157,112,43,195,152,117,46]]
	tq =[[[8,1,7,13,6,15,3,2,0,11,5,9,14,12,10,4],
		  [14,12,11,8,1,2,3,5,15,4,10,6,7,0,9,13],
		  [11,10,5,14,6,13,9,0,12,8,15,3,2,4,7,1],
		  [13,7,15,4,1,2,6,14,9,11,3,0,8,5,12,10]],
		 [[2,8,11,13,15,7,6,14,3,1,9,4,0,10,12,5],
		  [1,14,2,11,4,12,3,7,6,13,10,5,15,9,0,8],
 		  [4,12,7,5,1,6,9,10,0,14,13,8,2,11,3,15],
		  [11,9,5,1,12,3,13,14,6,4,7,15,2,0,8,10]]]

	mds_pol = 2**8 + 2**6 + 2**5 + 2**3 + 1
	rs_pol = 2**8 + 2**6 + 2**3 + 2**2 + 1

	Subkeys = []

	Sbox0 = []
	Sbox1 = []
	Sbox2 = []
	Sbox3 = []

	def q(self, x,i = 0):
		a0 = int(x/16)
		b0 = int(x%16)
		a1 = a0^b0
		b1 = a0^self.rotl(b0,1,4)
		b1 = b1^((8*a0)%16)
		a1 = self.tq[i][0][a1]
		b1 = self.tq[i][1][b1]
		a2 = a1^b1
		b2 = a1^self.rotl(b1,1,4)
		b2 = b2^ ((8*a1)%16)
		a2 = self.tq[i][2][a2]
		b2 = self.tq[i][3][b2]
		return 16*b2 + a2


	def g(self, x):
		x = [ int((x/(2**(8*i)))%(2**8)) for i in range(4)] 
		return self.Sbox0[x[0]] ^ self.Sbox1[x[1]] ^ self.Sbox2[x[2]]^ self.Sbox3[x[3]]
	
	def h(self, x, L0):
		x = [ int((x/(2**(8*i)))%(2**8)) for i in range(4) ]
		if len(L0) == 4:
			x[0] = (self.q(x[0],1)^ L0[3][0])
			x[1] = (self.q(x[1],0)^ L0[3][1])
			x[2] = (self.q(x[2],0)^ L0[3][2])
			x[3] = (self.q(x[3],1)^ L0[3][3])
		if len(L0) >= 3:
			x[0] = (self.q(x[0],1)^ L0[2][0])
			x[1] = (self.q(x[1],1)^ L0[2][1])
			x[2] = (self.q(x[2],0)^ L0[2][2])
			x[3] = (self.q(x[3],0)^ L0[2][3])
		
		
		x[0] = (self.q(x[0],0)^ L0[1][0])
		x[1] = (self.q(x[1],1)^ L0[1][1])
		x[2] = (self.q(x[2],0)^ L0[1][2])
		x[3] = (self.q(x[3],1)^ L0[1][3])

		x[0] = (self.q(x[0],0)^ L0[0][0])
		x[1] = (self.q(x[1],0)^ L0[0][1])
		x[2] = (self.q(x[2],1)^ L0[0][2])
		x[3] = (self.q(x[3],1)^ L0[0][3])
		
		x[0] = self.q(x[0],1)
		x[1] = self.q(x[1],0)
		x[2] = self.q(x[2],1)
		x[3] = self.q(x[3],0)
		
		return self.mds_lt_m([x[0], x[1], x[2], x[3]])
	
	def mds_lt_m(self, vec):
		result = 0
		for v in range(len(self.MDS)):
			new_val = 0
			for x in range(len(self.MDS[v])):
				new_val = new_val^self.mds_lt(self.MDS[v][x],vec[x])
			result= result + new_val*2**(8*v)
		return result
	def mds_lt(self, a, b):
			if a == 1:
				return b
			if a == 239:
				return self.MDS_Table[0][b]
			return self.MDS_Table[1][b]	

	def multgf(self, a, b, pol):
		if (b == 0):
			return 0
		p = 0
		while( b != 0):
			if(b & 1):
				p = p^a
			b = b>>1
			a = a<<1
			if (a > 255):
				a = a^pol
		return p 


	def matmulgf(self, mat, vec, pol):
		result = 0
		for v in range(len(mat)):
			new_val = 0
			for x in range(len(mat[v])):
				new_val = new_val^self.multgf(mat[v][x],vec[x], pol)
			result = result + new_val* 2**(8*(len(mat)-1-v))
		return result

	def PHT(self,a,b):
		num1=(a+b)%(2**32)
		num2=(a+2*b)%(2**32)
		return num1,num2

	def generateKeys(self,key):
		if len(key) <= 32:
			key = self.pad(key,32,'0')
		elif len(key) <= 48:
			key = self.pad(key,48,'0')
		elif len(key) <= 64:
			key = self.pad(key,64,'0')
		else:
			key = key[0:64]
		key = self.HexToBin(key)

		m = [ int(key[i:i+8],2) for i in range(0, len(key), 8) ]
		S = []
		for t in range(0,len(m),8):
			S.append(self.matmulgf(self.RS,m[t:t+8],self.rs_pol))
		L0=[]
		for l in S:
			L0.append([ int((l/(2**(8*(3-i)))%(2**8))) for i in range(4) ])
		L0 = L0[::-1]
		x = [0,0,0,0]
		S0 = [None]*256
		S1 = [None]*256
		S2 = [None]*256
		S3 = [None]*256
		for i in range(256):
			if len(L0) == 4:
				x[0] = (self.q(i,1)^ L0[3][0])
				x[1] = (self.q(i,0)^ L0[3][1])
				x[2] = (self.q(i,0)^ L0[3][2])
				x[3] = (self.q(i,1)^ L0[3][3])
				x[0] = (self.q(x[0],1)^ L0[2][0])
				x[1] = (self.q(x[1],1)^ L0[2][1])
				x[2] = (self.q(x[2],0)^ L0[2][2])
				x[3] = (self.q(x[3],0)^ L0[2][3])
				x[0] = (self.q(x[0],0)^ L0[1][0])
				x[1] = (self.q(x[1],1)^ L0[1][1])
				x[2] = (self.q(x[2],0)^ L0[1][2])
				x[3] = (self.q(x[3],1)^ L0[1][3])

				x[0] = (self.q(x[0],0)^ L0[0][0])
				x[1] = (self.q(x[1],0)^ L0[0][1])
				x[2] = (self.q(x[2],1)^ L0[0][2])
				x[3] = (self.q(x[3],1)^ L0[0][3])
			
				x[0] = self.q(x[0],1)
				x[1] = self.q(x[1],0)
				x[2] = self.q(x[2],1)
				x[3] = self.q(x[3],0)

			if len(L0) == 3:
				x[0] = (self.q(i,1)^ L0[2][0])
				x[1] = (self.q(i,1)^ L0[2][1])
				x[2] = (self.q(i,0)^ L0[2][2])
				x[3] = (self.q(i,0)^ L0[2][3])
				x[0] = (self.q(x[0],0)^ L0[1][0])
				x[1] = (self.q(x[1],1)^ L0[1][1])
				x[2] = (self.q(x[2],0)^ L0[1][2])
				x[3] = (self.q(x[3],1)^ L0[1][3])

				x[0] = (self.q(x[0],0)^ L0[0][0])
				x[1] = (self.q(x[1],0)^ L0[0][1])
				x[2] = (self.q(x[2],1)^ L0[0][2])
				x[3] = (self.q(x[3],1)^ L0[0][3])
			
				x[0] = self.q(x[0],1)
				x[1] = self.q(x[1],0)
				x[2] = self.q(x[2],1)
				x[3] = self.q(x[3],0)

			if len(L0) == 2:
				x[0] = (self.q(i,0)^ L0[1][0])
				x[1] = (self.q(i,1)^ L0[1][1])
				x[2] = (self.q(i,0)^ L0[1][2])
				x[3] = (self.q(i,1)^ L0[1][3])
				x[0] = (self.q(x[0],0)^ L0[0][0])
				x[1] = (self.q(x[1],0)^ L0[0][1])
				x[2] = (self.q(x[2],1)^ L0[0][2])
				x[3] = (self.q(x[3],1)^ L0[0][3])
			
				x[0] = self.q(x[0],1)
				x[1] = self.q(x[1],0)
				x[2] = self.q(x[2],1)
				x[3] = self.q(x[3],0)

			S0[i] = x[0] |(self.MDS_Table[1][x[0]]<<8)|(self.MDS_Table[0][x[0]]<<16)|(self.MDS_Table[0][x[0]]<<24)
			S1[i] = self.MDS_Table[0][x[1]]|(self.MDS_Table[0][x[1]]<<8)|(self.MDS_Table[1][x[1]]<<16)|(x[1]<<24)
			S2[i] = self.MDS_Table[1][x[2]]|(self.MDS_Table[0][x[2]]<<8)|(x[2]<<16)|(self.MDS_Table[0][x[2]]<<24)
			S3[i] = self.MDS_Table[1][x[3]]|(x[3]<<8)|(self.MDS_Table[0][x[3]]<<16)|(self.MDS_Table[1][x[3]]<<24)
		
		self.Sbox0 = S0
		self.Sbox1 = S1
		self.Sbox2 = S2
		self.Sbox3 = S3
			


		M_odd = []
		M_even = []
		for i in range(0,len(m),4):
			q = m[i]*2**(8*3)+m[i+1]*2**(8*2)+m[i+2]*2**(8)+m[i+3]
			q = [ int((q/(2**(8*(3-i)))%(2**8))) for i in range(4) ]
			if int(i/4)%2 == 1: 
				M_odd.append(q)
			else:
				M_even.append(q)
		rho = 2**24+2**16+2**8+1
		keys = []
		for i in range(20):
			A = self.h(2*i*rho,M_even)
			B = self.h((2*i+1)*rho ,M_odd)
			B = self.rotr(B,8,32)
			A,B = self.PHT(A,B)
			B = self.rotr(B,9,32)
			keys.append(A)
			keys.append(B)
		self.Subkeys = keys
	
	def encrypt_block(self,pt):
		pt = bytes.fromhex(pt)
		x = []
		for i in range(4):
			k = 0
			x.append(int.from_bytes(pt[4*i:4*i+4], "little"))
		for i in range(4):
			x[i] = x[i]^self.Subkeys[i]
		for i in range(16):
			nl0 = x[0]
			nl1 = x[1]
			x[0] = self.g(x[0])
			x[1] = self.g(self.rotr(x[1],8,32))
			x[0],x[1] = self.PHT(x[0],x[1])
			x[0] = (x[0] + self.Subkeys[2*i+8])%(2**32)
			x[1] = (x[1] + self.Subkeys[2*i+9])%(2**32)
			x[2] = x[2]^x[0]
			x[2] = self.rotl(x[2],1,32)
			x[3] = self.rotr(x[3],1,32)
			x[3] = x[3]^x[1]
			
			x[0] = x[2]
			x[1] = x[3]
			x[2] = nl0
			x[3] = nl1
		x = [x[2],x[3],x[0],x[1]]
		
		for i in range(4):
			x[i] = hex(x[i]^self.Subkeys[4+i])[2:].zfill(8)
			k = ''
			for j in range(0,len(x[i]),2):
				k = x[i][j:j+2] + k
			x[i] = k
		return (x[0] + x[1] + x[2] + x[3])
	
	def decrypt_block(self,pt):
		pt = bytes.fromhex(pt)
		x = []
		for i in range(4):
			k = 0
			x.append(int.from_bytes(pt[4*i:4*i+4], "little"))
		for i in range(4):
			x[i] = x[i]^self.Subkeys[4+i]
		for i in range(16):
			nl0 = x[0]
			nl1 = x[1]
			x[0] = self.g(x[0])
			x[1] = self.g(self.rotr(x[1],8,32))
			x[0],x[1] = self.PHT(x[0],x[1])
			x[0] = (x[0] + self.Subkeys[2*(15-i)+8])%(2**32)
			x[1] = (x[1] + self.Subkeys[2*(15-i)+9])%(2**32)
			x[2] = self.rotr(x[2],1,32)
			x[2] = x[2]^x[0]
			x[3] = x[3]^x[1]
			x[3] = self.rotl(x[3],1,32)
			
			x[0] = x[2]
			x[1] = x[3]
			x[2] = nl0
			x[3] = nl1
		x = [x[2],x[3],x[0],x[1]]
		for i in range(4):
			x[i] = hex(x[i]^self.Subkeys[i])[2:].zfill(8)
			k = ''
			for j in range(0,len(x[i]),2):
				k = x[i][j:j+2] + k
			x[i] = k
		return (x[0] + x[1] + x[2] + x[3])

	def encrypt(self, plaintext,mode = 'ECB',padding = 'ISO 7816-4',iv = ''):
		return self.encrypt_mode(32,plaintext, mode, padding, iv)

	def decrypt(self, plaintext,mode = 'CBC',padding = 'ISO 7816-4',iv = ''):
		return self.decrypt_mode(32,plaintext, mode, padding, iv)
