#!/usr/bin/env python27

import collections
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

def main():
    
    str1 = "this is a test"
    str2 = "wokka wokka!!!"
    hc = Hamming_Distance_Calculator(str1, str2)
    print "Hamming distance between str1 and str2:", hc.get_distance()

if __name__ == '__main__':
    main()
