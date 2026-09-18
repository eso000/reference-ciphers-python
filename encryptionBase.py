class EncryptionBase:

    def string_to_bin(self, s):
        return "".join([bin(ord(x))[2:].zfill(8) for x in s])

    def bin_to_string(self, s):
        result = ""
        while len(s) != 0:
            if int(s[0:8], 2) > 0 and int(s[0:8], 2) < 240:
                result = result + chr(int(s[0:8], 2))
            s = s[8:]
        return result

    def string_to_hex(self, s):
        result = ""
        for x in s:
            result = result + hex(ord(x))[2:].zfill(2)
        return result

    @staticmethod
    def hex_to_bin(s):
        mp = {
            "0": "0000",
            "1": "0001",
            "2": "0010",
            "3": "0011",
            "4": "0100",
            "5": "0101",
            "6": "0110",
            "7": "0111",
            "8": "1000",
            "9": "1001",
            "A": "1010",
            "B": "1011",
            "C": "1100",
            "D": "1101",
            "E": "1110",
            "F": "1111",
            "a": "1010",
            "b": "1011",
            "c": "1100",
            "d": "1101",
            "e": "1110",
            "f": "1111",
        }
        return "".join([mp[si] for si in s])

    @staticmethod
    def bin_to_hex(s):
        mp = {
            "0000": "0",
            "0001": "1",
            "0010": "2",
            "0011": "3",
            "0100": "4",
            "0101": "5",
            "0110": "6",
            "0111": "7",
            "1000": "8",
            "1001": "9",
            "1010": "a",
            "1011": "b",
            "1100": "c",
            "1101": "d",
            "1110": "e",
            "1111": "f",
        }
        return "".join([mp[s[i : i + 4]] for i in range(0, len(s), 4)])

    @staticmethod
    def bin_to_hex_le(s):
        mp = {
            "0000": "0",
            "0001": "1",
            "0010": "2",
            "0011": "3",
            "0100": "4",
            "0101": "5",
            "0110": "6",
            "0111": "7",
            "1000": "8",
            "1001": "9",
            "1010": "a",
            "1011": "b",
            "1100": "c",
            "1101": "d",
            "1110": "e",
            "1111": "f",
        }
        return "".join(
            [
                mp[s[i + 4 : i + 8][::-1]] + mp[s[i : i + 4][::-1]]
                for i in range(0, len(s), 8)
            ]
        )

    @staticmethod
    def hex_to_bin_le(s):
        mp = {
            "0": "0000",
            "1": "0001",
            "2": "0010",
            "3": "0011",
            "4": "0100",
            "5": "0101",
            "6": "0110",
            "7": "0111",
            "8": "1000",
            "9": "1001",
            "A": "1010",
            "B": "1011",
            "C": "1100",
            "D": "1101",
            "E": "1110",
            "F": "1111",
            "a": "1010",
            "b": "1011",
            "c": "1100",
            "d": "1101",
            "e": "1110",
            "f": "1111",
        }
        return "".join(
            [mp[s[i + 1]][::-1] + mp[s[i]][::-1] for i in range(0, len(s), 2)]
        )

    @staticmethod
    def bitwise_xor(bit_string1, bit_string2):
        minlenght = min(len(bit_string1), len(bit_string2))
        result = ""
        for i in range(minlenght):
            if bit_string1[i] == bit_string2[i]:
                result += "0"
            else:
                result += "1"
        return result

    @staticmethod
    def permutate(bit_string, perm, start=1):
        return "".join([bit_string[i - start] for i in perm])

    @staticmethod
    def rotl(s, shifts):
        if isinstance(s, str):
            for i in range(shifts):
                s = s[1 : len(s)] + s[0]
            return s
        if isinstance(s, list):
            result = []
            return s[shifts:] + s[:shifts]
            for i in range(shifts):
                for j in range(1, len(s)):
                    result.append(s[j])
                result.append(s[0])
                s = result
                result = []
            return s

    @staticmethod
    def rotr(s, shifts):
        if isinstance(s, str):
            for i in range(shifts):
                s = s[len(s) - 1] + s[0 : len(s) - 1]
            return s
        if isinstance(s, list):
            result = []
            for i in range(shifts):
                for j in range(1, len(s)):
                    result.append(s[j])
                result.append(s[0])
                s = result
                result = []
            return s

    def encrypt_block(self, plt):
        return plt

    def decrypt_block(self, plt):
        return plt

    def pad(self, st, leng, typ="bit"):
        if len(st) == 0:
            st = "00"
        if len(st) % 2 == 1:
            st += "0"
        l = leng - len(st)
        if l <= 0:
            return st
        if typ == "bit":
            st = self.hex_to_bin(st)
            l = l * 4
            st = st + "1"
            for x in range(1, l):
                st = st + "0"
            return self.bin_to_hex(st)
        if typ == "TBC":
            st = self.hex_to_bin(st)
            l = l * 4
            if st[len(st) - 1] == "1":
                c = "0"
            else:
                c = "1"
            for x in range(0, l):
                st = st + c
            return self.bin_to_hex(st)
        if typ == "byt":
            for x in range(0, int(l / 2)):
                st = st + "00"
            return st
        if typ == "ISO 7816-4":
            st = st + "80"
            for x in range(1, int(l / 2)):
                st = st + "00"
            return st
        if typ == "PKCS":
            l = int(l / 2)
            c = hex(l)[2:].zfill(2)
            for x in range(l):
                st = st + c
            return st
        if typ == "ANSI X9.23":
            l = int(l / 2)
            c = hex(l)[2:].zfill(2)
            for x in range(l - 1):
                st = st + "00"
            st = st + c
            return st
        if typ == "0":
            for x in range(0, int(l)):
                st = st + "0"
            return st

    @staticmethod
    def shift_left(bit_string, n):
        result = ""
        for x in range(n):
            bit_string = bit_string[1 : len(bit_string)] + "0"
        return bit_string

    @staticmethod
    def shift_right(bit_string, n):
        result = ""
        for x in range(n):
            bit_string = "0" + bit_string[0 : len(bit_string) - 1]
        return bit_string

    def encrypt_mode(self, block_size, plt, mode="CBC", padding="", iv=""):
        blocks = [
            plt[i : i + block_size] for i in range(0, len(plt), block_size)
        ]
        if len(blocks[-1]) < block_size:
            blocks[len(blocks) - 1] = self.pad(
                blocks[len(blocks) - 1], block_size, padding
            )

        if mode == "ECB":
            result = ""
            for block in blocks:
                result = result + self.encrypt_block(block)
            return result
        if mode == "CBC":
            result = ""
            if len(iv) != block_size:
                iv = self.pad(iv, block_size, padding)
            for block in blocks:
                nb = self.bitwise_xor(
                    self.hex_to_bin(block), self.hex_to_bin(iv)
                )
                nb = self.encrypt_block(self.bin_to_hex(nb))
                iv = nb
                result = result + nb
            return result

    def decrypt_mode(self, block_size, plt, mode="CBC", padding="", iv=""):
        blocks = [
            plt[i : i + block_size] for i in range(0, len(plt), block_size)
        ]
        if mode == "ECB":
            result = ""
            for block in blocks:
                result = result + self.decrypt_block(block)
            return result
        if mode == "CBC":
            result = ""
            if len(iv) != block_size:
                iv = self.pad(iv, block_size, padding)
            for block in blocks:
                nb = self.decrypt_block(block)
                nb = self.bitwise_xor(self.hex_to_bin(nb), self.hex_to_bin(iv))
                nb = self.bin_to_hex(nb)
                iv = block
                result = result + nb
            return result