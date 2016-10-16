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
            stream = '0' + stream
            stream_len = len(stream)

        return stream

    def set_decrypt_key(self, key):
        b = Bits(int=key, length=8)
        self.XOR_to_use = BitArray(b)

    def get_decrypt_key(self):
        return self.XOR_to_use.hex

    def set_cipher_stream(self, cipher_stream):
        if cipher_stream.startswith('0x'):
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
    main()
