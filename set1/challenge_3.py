"""
Cryptopals challenge 3 solution.
By Sandra Escandor-O'Keefe, 2016
"""

#!/usr/env python27
from bitstring import BitArray, Bits
from operator import itemgetter

class CharScore():

    def __init__(self):
        self.hex_stream = '' 
        self.score = 0
        self.key_used = 0 
        self.score_board = dict()

    def clear(self):
        self.__init__()

    def get_key(self):
        return self.key_used

    def get_hex_stream(self):
        return self.hex_stream

    def do_score(self, data_stream, key_used, is_hex=True):
        if is_hex:
            ascii_str = data_stream.decode('hex')
        else:
            ascii_str = data_stream

        """
        Letters are based off of frequency chart from:
        https://www.math.cornell.edu/~mec/2003-2004/cryptography/subs/frequencies.html
        """
        num_e = ascii_str.count('e')
        num_E = ascii_str.count('E')

        num_t = ascii_str.count('t')
        num_T = ascii_str.count('T')

        num_a = ascii_str.count('a')
        num_A = ascii_str.count('A')

        num_o = ascii_str.count('o')
        num_O = ascii_str.count('O')

        num_spaces = ascii_str.count(' ')

        
        curr_score = num_e + num_E + num_t + num_T + num_a + num_A \
                     + num_o + num_O + num_spaces

        if curr_score > self.score:
            self.key_used = key_used
            self.score = curr_score
            self.hex_stream = data_stream

        self.score_board[self.hex_stream] = curr_score

    def get_top_ten(self):
        for k,v in sorted(self.score_board.items(), reverse=True, key=itemgetter(1))[0:10]:
            print "stream:", k.decode('hex'), " score:", v


class Decrypter():

    def __init__(self):
        self.XOR_to_use = BitArray(hex='0x00')
        self.XOR_highest_freq = self.XOR_to_use
        self.cipher_stream = BitArray(hex='0x00')
        self.cipher_stream_length = 0
        self.output = BitArray(hex='0x00')

    def _ensure_padding(self, cipher_stream):
        stream = BitArray(hex=cipher_stream)
        stream_len = stream.len
        while stream_len % 8:
            stream.insert('0b0', 0)
            stream_len = stream_len + 1

        return stream

    def set_decrypt_key(self, key):
        b = Bits(int=key, length=8)
        self.XOR_to_use = BitArray(b)

    def get_decrypt_key(self):
        return self.XOR_to_use.hex

    def set_cipher_stream(self, cipher_stream):
        try:
            if type(cipher_stream) is str and cipher_stream.startswith('0x'):
                self.cipher_stream = self._ensure_padding(cipher_stream)
        except AttributeError:
            self.cipher_stream = self._ensure_padding(cipher_stream)

    def decrypt(self):
        self.output = BitArray(hex='0x00')
        skip_by = 8
        for i in xrange(0, self.cipher_stream.len, skip_by):
            result = self.cipher_stream[i:skip_by] ^ self.XOR_to_use
            self.output.append(result)
            skip_by += 8

        return self.output

class Decrypt_Key_Solver():

    def __init__(self, cipher_hex_stream):
        self.cipher_hex_stream = cipher_hex_stream
        self.decrypter = Decrypter()
        self.scorer = CharScore()
        self.key_used = ""
        self.deciphered_stream = ""

    def get_key_used(self):
        return self.key_used

    def get_deciphered_stream(self):
        return self.deciphered_stream

    def solve(self):
        self.decrypter.set_cipher_stream(self.cipher_hex_stream)
        for i in range(-128, 127):
            self.decrypter.set_decrypt_key(i)
            self.scorer.do_score(str(self.decrypter.decrypt().hex), i)

        self.key_used = self.scorer.get_key()
        self.deciphered_stream = self.scorer.get_hex_stream().decode('hex')

def main():
    
    solver = Decrypt_Key_Solver('0x1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736')
    solver.solve()

    print "Key used:", solver.get_key_used()
    print "Deciphered stream as:", solver.get_deciphered_stream()

def test_main():

    stream_to_solve = '0x1d1f0b024f4e1a65490e130b4e0145000164541d334e5200540d4d04533c1e49094f4c1a2b05471109640700160c171d52300013054f48456516380608464f597e620c0f0d061a004204011a11527f003a1a494f481d533a520141064c5f62060954171449330b010f071d784852074548414f54741d4900160030654902000b4e1001104d071f1b7869520154075302533b06490f4f005f2b493354101a05110c4d0203523d000b0d4e0d544f1c5e0b19120a534e6201471d0017050c424d01221c3441354f2a3b4f1b5337070c150e071a2a49065445070507452c0a1d5237001d490001450e17395e1d044f77433b1c14150c49084500670113063746550f53480000073b5201411b471a160c02070b4e00160b4d021b1778691f0700114f0103351763094f49562749060d110b490a00004e1a5230541b4e4b624e4f53355208024f454e301d06540b4e0045421d0f54782c47524e0d31411b163b171046184e5b2e1a02540a641d160a0b0354173c53520b0000000a072413490900471a11494715451b020c451d0f101f3300061d550c47005365405a384f0d712d0208540a0b1e0a452b1c131d7855194e00014502533c1f1a001d43553163121106020f040c041a170a314c160d4f1b2a48533a170f024f4e1a2a1d1e0106000b116f4d0f54133d411417471a0001533517011318541a484e471d003d040a45403d191d784f36024c002a07017352060501491d62064715451c490a0d034e360621551e4e451854161d741d0e1502004e2e49281145004913174d1c171b3d4d191d501a451b792152064109594f3049471b031c496f0a4a0213063657170b0007500e16741d1d0c434e1a2b0547270a4e442a451429105237451d170007001d11360b0c1565505d271d471d0d0f1a0a0b4d01111d784e520f001c00653a7a24070d0e695f3b1947114927040608034e1516344b524e48060026072c111d0f4f4f43371a0613170202454504017e1d284e011d4f4852061435160e134f544a21100954330005042c08075417344e52000007000a0331130c03164e1a650814540d4e0145170c1d151732431b494c03001d09741e0c6b00491d230d001b130049170c0a1a541b3f411d092a0400071c335201410754552506111a45061a0d174d01137837001d494509410a532d060c373f504927496d0015074e16450c0a1819780017034e265a4f2035060c4116545f201a141c11074e020a034e20173d531c4e521849481c741b0c4148004f360e131d420a1e45360c0519063b00554e410f4e4f1a3c5200040e4654360a6d1b451c190045080117523600520655000007075e1d490807005b27004727451a1901124d0054173c4d5201520d52654b741c044106451a2d4540440c4e101c0443642d072a0017054e06000e07743d490f4f005b620c0b1d45371c450a141d130631071a1a000700003a371c1a0403491a11490853450b040104090a1a063a00134e0709534f1b740b00120d4c5462062e3145014904450c02195239002b1b5248490c1a73130f154f4f492749061f040a0c01174d2200063d570606440b4f433a315206150a4454271d470100640606084d1e171d3d41160a4e1c424f023517630e4f415462081311084e44241c040b541c2f451764791d540014200608414f411a2702471b49171c1745080a031d3f2a1d0d4d484e4f0526100d41010053251d0e540a0963361c404e180b2c41521b4b48550653355e0e4107541a2d4500540d1a490a450264180b2c41521b4b485506533b0500040d591a2d1e0e110717490a6f0c4e1b1c3944100149484e4f1f2d0608411a4b1a3700471d09171c01004d64180b2c41521b4b485506533b17064d2c4d1a2c49025400060845350c4e1c063e4e0b03530b570616360b10141c59536e1a1e1d453e08450d19081a0b3553112f4c1c4c4f1c30000716654c43360847010e4e1c0c491a07111021631f4e4e484f0a1c78310441012a563b1d0654100549100c4d'

    solver = Decrypt_Key_Solver(stream_to_solve)
    solver.solve()

    print "Key used:", solver.get_key_used()
    print "Deciphered stream as:", solver.get_deciphered_stream()

def main_orig():
    """
    Algorithm:
    -initiate single-byte XOR to use
    -XOR with given hex encoded string
    -check frequency of the letters "ETA" and
     record frequency.
    -increment single-byte XOR

    -Do the above in a loop, with increasing single-byte XOR.
    -After loop, check which single-byte XOR produced the largest
     frequency of the letters "ETA"
    """

    dcrypt = Decrypter()
    dcrypt.set_cipher_stream('0x1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736')
    
    scorer = CharScore()

    for i in range(-128, 127):
        dcrypt.set_decrypt_key(i)
        scorer.do_score(str(dcrypt.decrypt().hex), i)

    print "Highest scoring deciphered stream:"
    print "Key used:", str(hex(scorer.get_key()))
    print "Stream deciphered to:", scorer.get_hex_stream().decode('hex')

    print "---- TOP TEN scoring streams ----"
    scorer.get_top_ten()


if __name__ == '__main__':
    main_orig()
