#!/usr/env python27
from bitstring import BitArray, Bits

class CharScore():

    def __init__(self):
        self.hex_stream = '' 
        self.score = 0
        self.key_used = 0 

    def get_key(self):
        return self.key_used

    def get_hex_stream(self):
        return self.hex_stream

    def do_score(self, hex_stream, key_used):
        ascii_str = hex_stream.decode('hex')

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

        curr_score = curr_score 

        if curr_score > self.score:
            self.key_used = key_used
            self.score = curr_score
            self.hex_stream = hex_stream



class Decrypter():

    def __init__(self):
        self.XOR_to_use = BitArray(hex='0x00')
        self.XOR_highest_freq = self.XOR_to_use
        self.cipher_stream = BitArray(hex='0x00')
        self.cipher_stream_length = 0
        self.output = BitArray(hex='0x00')

    def _ensure_padding(self, cipher_stream):
        stream = cipher_stream[2:]
        stream_len = len(stream)
        if stream_len % 2:
            stream = '0' + stream

        return stream

    def set_decrypt_key(self, key):
        b = Bits(int=key, length=8)
        self.XOR_to_use = BitArray(b)

    def get_decrypt_key(self):
        return self.XOR_to_use.hex

    def set_cipher_stream(self, cipher_stream):
        if cipher_stream.startswith('0x'):
            cipher_stream = self._ensure_padding(cipher_stream)
            self.cipher_stream = BitArray(hex=cipher_stream)

    def decrypt(self):
        self.output = BitArray(hex='0x00')
        skip_by = 8
        for i in xrange(0, self.cipher_stream.len, skip_by):
            result = self.cipher_stream[i:skip_by] ^ self.XOR_to_use
            self.output.append(result)
            skip_by += 8

        return self.output


def main():
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

    print str(scorer.get_key())
    #print scorer.get_hex_stream().decode('hex')

    dcrypt.set_decrypt_key(82)
    print (dcrypt.decrypt().hex).decode('hex')


if __name__ == '__main__':
    main()
