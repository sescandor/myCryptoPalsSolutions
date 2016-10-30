#!/usr/bin/env python27

import collections
from challenge_1 import Base64_To_Hex
from challenge_3 import Decrypter, Decrypt_Key_Solver
from challenge_4 import Data_reader
from bitstring import BitArray
from operator import itemgetter


class Hamming_Distance_Calculator():

    def __init__(self, bit_str1, bit_str2):
        self.bit_str1 = bit_str1
        self.bit_str2 = bit_str2

    def _pre_process(self):
        if self.bit_str1.len != self.bit_str2.len:
            len_map = {self.bit_str1.len: self.bit_str1, self.bit_str2.len: self.bit_str2}
            len_map = collections.OrderedDict(sorted(len_map.items(), reverse=True))

            longer_len = len_map.items()[0][0] 
            shorter_len = len_map.items()[1][0]
            longer_stream = len_map.items()[0][1]
            shorter_stream = len_map.items()[1][1]

            for i in range(0, longer_len - shorter_len):
                shorter_stream = BitArray(bin='0') + shorter_stream

            self.bit_str1 = longer_stream 
            self.bit_str2 = shorter_stream 


    def get_distance(self):
        """
        Assuming that the two bit strings are the same length:
        1. XOR the two bit strings. This will calculate which positions are different.
        2. Count the number of set bits from the result of step 1.
        """
        self._pre_process()

        bit_str_len = self.bit_str1.len
        resulting_diff_stream = BitArray(bin='0')

        for i in range(0, bit_str_len):
            result = self.bit_str1[i] ^ self.bit_str2[i]
            resulting_diff_stream.append(BitArray(bool=result))

        return resulting_diff_stream.count(1)

class Keysize_Estimator():

    def __init__(self, cipher_data):
        self.cipher_data = cipher_data
        self.size_range = range(2, 40)
        self.key_to_edit_dist = dict()

    def _get_smallest_keys_to_edit_dist(self):
        key_list = sorted(self.key_to_edit_dist.items(), key=itemgetter(1))
        keys_with_smallest_edit_dist = list() 
       
        for k,v in key_list:
            keys_with_smallest_edit_dist.append(k) 

        return keys_with_smallest_edit_dist[0:3] 
            
    def get_edit_distances(self):
        for keysize in self.size_range:
            num_bits = keysize * 8
            first = self.cipher_data[0:num_bits]
            second = self.cipher_data[num_bits:2*num_bits]
            hamming_dist = Hamming_Distance_Calculator(first, second).get_distance()
            normalized = hamming_dist / keysize
            self.key_to_edit_dist[keysize] = normalized

        return self._get_smallest_keys_to_edit_dist()


class Repeating_XOR_Breaker():
    
    def __init__(self, cipher_data):
        self.cipher_data = cipher_data
        self.keysize_estimator = Keysize_Estimator(self.cipher_data)
        self.key_to_transposed_streams = dict()
        self.candidate_keysizes = list()

    def _get_candidate_keysizes(self):
        self.candidate_keysizes = self.keysize_estimator.get_edit_distances()

    def _get_keysize_to_transposed_streams(self):
        return self.key_to_transposed_streams

    def _set_candidate_keysizes(self, keysizes_list):
        self.candidate_keysizes = keysizes_list

    def _transpose(self):
        
        """
        Each row in transposed_streams corresponds to the nth byte
        of a block. For example, transposed_streams[0] corresponds to
        the 1st byte of every keysize block; transposed_streams[1] 
        corresponds to the 2nd byte of every keysize block; and so on. 
        """
        
        for candidate_keysize in self.candidate_keysizes:
            transposed_streams = {bucket: BitArray() for bucket in
                                  range(candidate_keysize)}

            skip_by_bits = (candidate_keysize) * 8
            
            for i in xrange(0, self.cipher_data.len, skip_by_bits):
                
                n = 0
                for stream in transposed_streams:
                    start = i + n
                    end = i + n + 8
                    transposed_streams[stream].append(self.cipher_data[start:
                                                                       end])
                    n = n + 8

            self.key_to_transposed_streams[candidate_keysize] = transposed_streams

    def solve(self):
        candidate_keys = list()
        self._get_candidate_keysizes()
        self._transpose()
        for candidate_keysize, transposed_stream in self.key_to_transposed_streams.iteritems():
            print "candidate_keysize:", candidate_keysize
            key = list()
            for bucket in transposed_stream:
                stream_to_solve = '0x' + transposed_stream[bucket].hex
                solver = Decrypt_Key_Solver(stream_to_solve)
                solver.solve()
                key_used = solver.get_key_used()
                key.append(key_used)

            candidate_keys.append(key)

        return candidate_keys


class ExtendedKeyDecrypter(Decrypter):

    def __init__(self):
        Decrypter.__init__(self)
        self.key_len = 0

    def set_decrypt_key(self, key):
        self.XOR_to_use = BitArray(hex=key)
        self.key_len = self.XOR_to_use.len

    def _ensure_padding(self, cipher_stream):
        stream = BitArray(hex=cipher_stream)
        stream_len = stream.len
        while stream_len % self.key_len:
            stream.insert('0b0', stream.len)
            stream_len = stream_len + 1

        return stream

    def decrypt(self):
        result = BitArray(hex='0x00')
        skip_by = self.key_len
        for i in xrange(0, self.cipher_stream.len, skip_by):
            xor_res = self.cipher_stream[i:skip_by] ^ self.XOR_to_use
            result.append(xor_res)
            skip_by += self.key_len

        return result 


def test_transpose():
    test_breaker = Repeating_XOR_Breaker(BitArray(hex="0x12341234"))
    test_list = list()
    test_list.append(2)
    test_breaker._set_candidate_keysizes(test_list)
    test_breaker._transpose()

    streams = test_breaker._get_keysize_to_transposed_streams()
    print streams[2]


def main():
    """
    1. Get file.
    2. Convert from base64 to hex string representation.
    3. Convert hex string representation to BitArray.
    4. Feed into Repeating_XOR_Breaker
    """
    cipher_source = "https://cryptopals.com/static/challenge-data/6.txt"
    cipher_reader = Data_reader(cipher_source)

    data = cipher_reader.get_data()
    data = ''.join(data)
    converted = Base64_To_Hex(data).convert()
    data_to_break = BitArray(hex=converted)
    breaker = Repeating_XOR_Breaker(data_to_break)

    candidate_keys = breaker.solve()

    print "Candidate Keys:", candidate_keys

    for key_set in candidate_keys:
        whole_key = BitArray()
        for key in key_set:
            whole_key.append(BitArray(int=key, length=8))

        print "whole_key:", whole_key
        decrypter = ExtendedKeyDecrypter()
        decrypter.set_decrypt_key(whole_key.hex)
        decrypter.set_cipher_stream('0x' + data_to_break.hex)
        print decrypter.decrypt().hex.decode('hex')


if __name__ == '__main__':
    main()
