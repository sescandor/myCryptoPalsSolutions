import binascii
import base64
import sys

class Hex_To_Base64():

    def __init__(self, hex_to_convert):
        self.to_convert = hex_to_convert

    def convert(self):
        to_bin = binascii.a2b_hex(self.to_convert)

        to_b64 = (binascii.b2a_base64(to_bin)).rstrip('\n')

        return to_b64

if __name__ == '__main__':
    string_to_convert = '49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'

    string_should_be = 'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t'

    toConvert_b64 = Hex_To_Base64(string_to_convert).convert() 

    if toConvert_b64 == string_should_be:
        print "Successfully converted to base64!"

