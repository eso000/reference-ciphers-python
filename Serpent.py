from encryptionBase import *


class Serpent(encryptionBase):
    SBoxes = [[[ 3, 8,15, 1,10, 6, 5,11,14,13, 4, 2, 7, 0, 9,12 ],#SB
                    [15,12, 2, 7, 9, 0, 5,10, 1,11,14, 8, 6,13, 3, 4 ],
                    [ 8, 6, 7, 9, 3,12,10,15,13, 1,14, 4, 0,11, 5, 2 ],
                    [ 0,15,11, 8,12, 9, 6, 3,13, 1, 2, 4,10, 7, 5,14 ],
                    [ 1,15, 8, 3,12, 0,11, 6, 2, 5, 4,10, 9,14, 7,13 ],
                    [15, 5, 2,11, 4,10, 9,12, 0, 3,14, 8,13, 6, 7, 1 ],
                    [ 7, 2,12, 5, 8, 4, 6,11,14, 9, 1,15,13, 3,10, 0 ],
                    [ 1,13,15, 0,14, 8, 2,11, 7, 4,12,10, 9, 3, 5, 6 ]],
                [[13, 3,11, 0,10, 6, 5,12, 1,14, 4, 7,15, 9, 8, 2 ],#invSB
                    [ 5, 8, 2,14,15, 6,12, 3,11, 4, 7, 9, 1,13,10, 0 ],
                    [12, 9,15, 4,11,14, 1, 2, 0, 3, 6,13, 5, 8,10, 7 ],
                    [ 0, 9,10, 7,11,14, 6,13, 3, 5,12, 2, 4, 8,15, 1 ],
                    [ 5, 0, 8, 3,10, 9, 7,14, 2,12,11, 6, 4,15,13, 1 ],
                    [ 8,15, 2, 9, 4, 1,13,14,11, 6, 5, 3, 7,12,10, 0 ],
                    [15,10, 1,13, 5, 3, 6, 0, 4, 9,14, 7, 2,12, 8,11 ],
                    [ 3, 0, 6,13, 9,14,15, 8, 5,12,11, 7,10, 1, 4, 2 ]]]


    Subkeys = []

    def rotl(self, a,s,n):
        return (((a>>s)|(a<< n-s))%(2**n))
    
    def rotr(self, a,s,n):
        return (((a<<s)|(a>> n-s))%(2**n))


    def applySBox(self, X, n, d = 0):
        Xn =[0,0,0,0]
        for x in range(32):

            newbits = self.SBoxes[d][n][((X[0]>>x)%2) <<0 |
                                         ((X[1]>>x)%2) <<1 |
                                         ((X[2]>>x)%2) <<2 |
                                         ((X[3]>>x)%2) <<3 ]
            Xn[0] |= ((newbits >> 0)%2) << x
            Xn[1] |= ((newbits >> 1)%2) << x
            Xn[2] |= ((newbits >> 2)%2) << x
            Xn[3] |= ((newbits >> 3)%2) << x
        return Xn
    
    def generateKeys(self,key):
        key = self.pad(key,int(256/4),'bit')
        key = key[0:int(256/4)]
        key = self.HexToBin_le(key)
        w = [ int(key[i:i+32],2) for i in range(0,256,32) ]
        for i in range(8, 140):
            wi = w[i - 8]^ w[i - 5]^ w[i - 3]^ w[i - 1]^2644438137^ int((bin(i-8)[2:].zfill(32))[::-1],2)
            wi = self.rotl(wi,11,32)
            w.append(wi)
        sk1 = []
        for i in range(33):
            k = self.applySBox([w[4*i+8],w[4*i+1+8],w[4*i+2+8],w[4*i+3+8]],(((32 + 3 - i) % 32)%8))
            sk1.append(k)
        self.Subkeys = sk1
    
    def LT(self,X):
        X[0] = self.rotl(X[0], 13,32)
        X[2] = self.rotl(X[2], 3,32)
        X[1] = X[1]^X[0]^X[2]
        X[3] = X[3]^X[2]^(X[0]>>3)
        X[1] = self.rotl(X[1], 1,32)
        X[3] = self.rotl(X[3], 7,32)
        X[0] = X[0]^X[1]^X[3]
        X[2] = X[2]^X[3]^ (X[1]>>7)
        X[0] = self.rotl(X[0], 5,32)
        X[2] = self.rotl(X[2], 22,32)
        return X
    def LTinverse(self,X):
        X[2] = self.rotr(X[2], 22,32)
        X[0] = self.rotr(X[0], 5,32)
        X[2] = X[2]^X[3]^ (X[1]>>7)
        X[0] = X[0]^X[1]^X[3]
        X[3] = self.rotr(X[3], 7,32)
        X[1] = self.rotr(X[1], 1,32)
        X[3] = X[3]^X[2]^(X[0]>>3)
        X[1] = X[1]^X[0]^X[2]
        X[2] = self.rotr(X[2], 3,32)
        X[0] = self.rotr(X[0], 13,32)
        return X

    
    def encrypt_block(self, X):
        X = self.HexToBin_le(X)
        X = [int(X[32*i:32*i+32],2) for i in range(4)]
        for x in range(32):
            X = [X[i]^self.Subkeys[x][i] for i in range(4)]
            X = self.applySBox(X,int(x%8))
            if x == 31:
                break
            X = self.LT(X)
        X = "".join([bin(X[i]^self.Subkeys[32][i])[2:].zfill(32) for i in range(4)])
        return self.BinToHex_le(X)



    def decrypt_block(self,X):
        X = self.HexToBin_le(X)
        X = [int(X[32*i:32*i+32],2) for i in range(4)]
        X = [X[i]^self.Subkeys[32][i] for i in range(4)]
        X = self.applySBox(X,int(31%8),d=1)
        X = [X[i]^self.Subkeys[31][i] for i in range(4)]
        for x in range(31):
            X = self.LTinverse(X)
            X = self.applySBox(X,int((30-x)%8),d=1)
            X = [X[i]^self.Subkeys[30-x][i] for i in range(4)]
        X = "".join([bin(X[i])[2:].zfill(32) for i in range(4)])
        return self.BinToHex_le(X)




    def encrypt(self, plaintext,mode = 'CBC',padding = 'bit',iv = ''):
        return self.encrypt_mode(32,plaintext, mode, padding, iv)

    def decrypt(self, plaintext,mode = 'CBC',padding = 'bit',iv = ''):
        return self.decrypt_mode(32,plaintext, mode, padding, iv)
