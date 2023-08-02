from cryptography.hazmat.primitives.ciphers import Cipher,algorithms,modes
from cryptography.hazmat.backends import default_backend
from math import ceil

backend = default_backend()

def strxor(a, b):  # xor two strings of different lengths
  if len(a) > len(b):
    return "".join([chr(ord(x) ^ ord(y)) for (x, y) in zip(a[:len(b)], b)])
  else:
    return "".join([chr(ord(x) ^ ord(y)) for (x, y) in zip(a, b[:len(a)])])

def from_hex(s):
    return ''.join([chr(int(''.join(c), 16)) for c in zip(s[0::2], s[1::2])])

def to_hex(i):
   return f'{i:x}'


def extract_IV(ciphertext): 
    return ciphertext[0:32]

def get_num_of_blocks(ciphertext):
    return ceil(len(ciphertext)/32)

def encrypt_IVs(IVb,ciphertext,keyb):
    L = get_num_of_blocks(ciphertext)
  
   
    
    algorithm = Cipher(algorithms.AES(keyb),modes.ECB(),backend)
    encryptor = algorithm.encryptor()
    decryptedx = ""
    for i in range(0,L+1): 
        encryptedb = encryptor.update(IVb)
        decryptedx+= encryptedb.hex()  
        IVb = bytes.fromhex(to_hex(int(IVb.hex(),16)+1)) 
    encryptor.finalize()
    return decryptedx 
    
def CTR_d(ciphertext,key): 

    IV  = extract_IV(ciphertext)
    IVb = bytes.fromhex(IV)

    keyb = bytes.fromhex(key)

    ciphertext_without_IV = ciphertext[32::]
    encrypted_IVs = encrypt_IVs(IVb,ciphertext_without_IV,keyb)

    return strxor(from_hex(encrypted_IVs),from_hex(ciphertext_without_IV))


def CBC_d(ciphertext,key):
    IV = extract_IV(ciphertext)
    IVb = bytes.fromhex(IV)

    keyb = bytes.fromhex(key)

    ciphertext_without_IV = ciphertext[32::]

    blocks = [ciphertext_without_IV[i:i+32] for i in range(0, len(ciphertext_without_IV), 32)]

    algorithm = Cipher(algorithms.AES(keyb),modes.ECB(),backend)
    decryptor = algorithm.decryptor()
    decryptedx = ''
    
    old = IV 
    for b in blocks:
      decryptedb = decryptor.update(bytes.fromhex(b)) 
      decryptedx += strxor(from_hex(decryptedb.hex()),from_hex(old))
      old = b 

    decryptor.finalize()  

    ending = decryptedx[len(decryptedx)-1]
    if ord(ending) <=31 and ord(ending)>=0:
        decryptedx = decryptedx[0:len(decryptedx)-ord(ending)]
    
    return decryptedx

def main():
    key1 = "140b41b22a29beb4061bda66b6747e14"
    key2 = "36f18357be4dbd77f050515c73fcf9f2"
  
    cipher1 = "4ca00ff4c898d61e1edbf1800618fb2828a226d160dad07883d04e008a7897ee2e4b7465d5290d0c0e6c6822236e1daafb94ffe0c5da05d9476be028ad7c1d81"
    cipher2 = "5b68629feb8606f9a6667670b75b38a5b4832d0f26e1ab7da33249de7d4afc48e713ac646ace36e872ad5fb8a512428a6e21364b0c374df45503473c5242a253"
    cipher3 = "69dda8455c7dd4254bf353b773304eec0ec7702330098ce7f7520d1cbbb20fc388d1b0adb5054dbd7370849dbf0b88d393f252e764f1f5f7ad97ef79d59ce29f5f51eeca32eabedd9afa9329"
    cipher4 = "770b80259ec33beb2561358a9f2dc617e46218c0a53cbeca695ae45faa8952aa0e311bde9d4e01726d3184c34451"
     
    m1 = CBC_d(cipher1,key1)
    m2 = CBC_d(cipher2,key1)
    m3 = CTR_d(cipher3,key2)
    m4 = CTR_d(cipher4,key2)

  
    print("m1 = "+m1)
    print("m2 = "+m2)
    print("m3 = "+m3)
    print("m4 = "+m4) 
   
    
main() 

