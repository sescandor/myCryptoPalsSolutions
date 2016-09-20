import binascii

def fixor(input1, input2):

  input1 = int(input1,16)
  input2 = int(input2,16)

  m = input1 ^ input2

  print hex(m)

if __name__ == '__main__':

    input1 = '1c0111001f010100061a024b53535009181c'
    input2 = '686974207468652062756c6c277320657965' 

    fixor(input1, input2)
