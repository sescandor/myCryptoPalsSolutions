#!/usr/bin/env python27

import collections
from challenge_3 import Decrypt_Key_Solver
from bitstring import BitArray

class Hamming_Distance_Calculator():

    def __init__(self, str1, str2):
        self.bit_str1 = BitArray(hex=str1.encode('hex')) 
        self.bit_str2 = BitArray(hex=str2.encode('hex')) 

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

    def _get_smallest_keys_to_edit_dist():
        ordered_by_edit_dist = collections.OrderedDict(sorted(self.key_to_normalized_dist.values(), reverse=True))

        return ordered_by_edit_dist[0:3] 
            
    def get_edit_distances():
        for keysize in self.size_range:
            num_bits = keysize * 8
            first = self.cipher_data[0:num_bits]
            second = self.cipher_data[num_bits:2*num_bits]
            hamming_dist = Hamming_Distance_Calculator(first, secod)
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
            transposed_streams = {bucket: [] for bucket in
                                  range(candidate_keysize)}

            skip_by_bits = (candidate_keysize) * 8
            print "skip_by_bits:", skip_by_bits
            for i in xrange(0, self.cipher_data.len, skip_by_bits):
                print "processing", self.cipher_data[i:]
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
            key = list()
            for bucket in transposed_stream:
                solver = Decrypt_Key_Solver(bucket)
                key.append(solver.get_key_used())

            candidate_keys.append(key)

        return candidate_keys

def main():
    """
    1. Get file.
    2. Convert from base64 to hex string representation.
    3. Convert hex string representation to BitArray.
    4. Feed into Repeating_XOR_Breaker
    """
    test_breaker = Repeating_XOR_Breaker(BitArray(hex="0x12341234"))
    test_list = list()
    test_list.append(2)
    test_breaker._set_candidate_keysizes(test_list)
    test_breaker._transpose()
    
    streams = test_breaker._get_keysize_to_transposed_streams()
    print streams[2]  

if __name__ == '__main__':
    main()
