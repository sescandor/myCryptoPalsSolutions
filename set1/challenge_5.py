#!/user/bin/env python27

"""
Cryptopals set 1 Challenge 5 solution.
By Sandra Escandor-O'Keefe, 2016
"""

from bitstring import BitArray

class Encryptor():

    def __init__(self, key):
        self.key = BitArray(hex=key.encode('hex'))
        self.data_to_encrypt = None
        self.result_cipher = BitArray(bin='0') 

    def _l_padding(self, data_stream):
        stream = BitArray(hex=data_stream.encode('hex'))
        stream_len = stream.len
        while stream_len % self.key.len:
            stream = BitArray(bin='0') + stream
            stream_len = stream.len
    
        return stream

    def _pad_to_hex_size(self):
        stream = self.result_cipher
        stream_len = stream.len
        while stream_len % 8:
            stream = BitArray(bin='0') + stream
            stream_len = stream.len

        self.result_cipher = stream

    def encrypt(self, data):
        self.data_to_encrypt = self._l_padding(data)
        skip_by = self.key.len
        for pos in xrange(0, self.data_to_encrypt.len, skip_by):
            result = self.data_to_encrypt[pos:skip_by] ^ self.key
            self.result_cipher.append(result)
            skip_by += self.key.len 

        self._pad_to_hex_size()

        return self.result_cipher.hex 

def main():
    crypt = Encryptor("ICE")
    ciphertext = crypt.encrypt("Burning 'em, if you ain't quick and nimble")
    ciphertext = crypt.encrypt("I go crazy when I hear a cymbal")
    print ciphertext

if __name__ == '__main__':
    main()

        
