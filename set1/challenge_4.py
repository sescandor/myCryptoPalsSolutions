#!/usr/bin/env python27

"""
Cryptopals Set 1 - Challenge 4 solution.
By Sandra Escandor-O'Keefe, 2016.
"""

import wget
from challenge_3 import Decrypter, CharScore


class Data_reader():

    def __init__(self, url_source):
        self.cipher_source = url_source
        self.filename = None
        self.data = None

    def _read(self):
        self.filename = wget.download(self.cipher_source)
        print "Downloaded:", self.filename

    def get_data(self):
        self._read()
        with open(self.filename) as f:
            self.data = f.readlines()

        return self.data


def main():
    dcrypter = Decrypter()
    scorer = CharScore()
    cipher_source = 'https://cryptopals.com/static/challenge-data/4.txt'
    cipher_reader = Data_reader(cipher_source)
    
    data = cipher_reader.get_data()

    decrypt_dict = dict()
   
    print "num lines in data:", len(data)

    for line in data:
        dcrypter.set_cipher_stream('0x' + line)

        for key in range(-128, 127):
            dcrypter.set_decrypt_key(key)
            scorer.do_score(str(dcrypter.decrypt().hex), key)

        deciphered = scorer.get_hex_stream().decode('hex')
        decrypt_dict[deciphered] = scorer.get_key() 
        scorer.clear()


    for deciphered_text, cipher_key in decrypt_dict.iteritems():
        scorer.do_score(deciphered_text, cipher_key, False) 
   
    print "Likely:", scorer.get_hex_stream()
    print "Encrypted with key:", scorer.get_key()

if __name__ == '__main__':
    main()
