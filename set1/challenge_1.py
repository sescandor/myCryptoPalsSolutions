import binascii
import base64
import sys

if __name__ == '__main__':
  stringToConv = '49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'

  stringShouldBe = 'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t'

  hex = stringToConv.decode("hex") 
  
  toConvert_toBin = binascii.a2b_hex(stringToConv)

  toConvert_b64 = (binascii.b2a_base64(toConvert_toBin)).rstrip('\n')

  if toConvert_b64 == stringShouldBe:
    print "Successfully converted to base64!"

