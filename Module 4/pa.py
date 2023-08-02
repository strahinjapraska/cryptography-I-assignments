import urllib.request 
import urllib.error 
import urllib.parse
from termcolor import colored 

blocksize = 16 
TARGET = 'http://crypto-class.appspot.com/po?er='
#--------------------------------------------------------------
# padding oracle
#--------------------------------------------------------------
class PaddingOracle(object):
    def query(self, q):
        target = TARGET + urllib.parse.quote(q)    # Create query URL
        req = urllib.request.Request(target)         # Send HTTP request to server
        try:
            f = urllib.request.urlopen(req)          # Wait for response
        except urllib.error.HTTPError as e:          
            print ("We got: %d" % e.code)     # Print response code
            if e.code == 404:
                return True # good padding
            return False # bad padding

po = PaddingOracle()


def break_into_blocks(c):
    b = []
    while c: 
        b.append(c[:32])
        c = c[32:]

    return b 

def btoi(b):
    return int.from_bytes(b,"big")

def xor(x,y,z):
    r = btoi(x) ^ btoi(y) ^ btoi(z)
    return r.to_bytes(len(x), "big")

def query(blocks):
    final_message = ''
    for k in range(len(blocks)-1): 
        m = bytearray(blocksize) 
        for i in range(1,blocksize+1):
            pad = bytes([i]*blocksize)
            r = blocksize - i 
            
            for g in range(256): 
                m[r]=g
                b = bytes.fromhex(blocks[k])
                forgery = xor(pad,m,b).hex() 
                q = forgery + blocks[k+1]
                if(po.query(q)):
                    print(colored('found','green'))    
                    break   
                print(k,i,g)
        final_message+=bytes(m).decode('ascii',errors='ignore')
    print(final_message)

def main():    
    # TODO speed up the attack with frequency analysis 
    # The Magic Words are Squeamish Ossifrage
    c = 'd2609e1c6f3b832e8a586d8fc5429e6e78300087da110b688b051d870b452ad3b51a70399050a5d76ae7d37f36f1027bed74ee638e0f645d03d07228bd4fd36e'
    blocks = break_into_blocks(c)
    print(len(blocks))
    query(blocks)
    
  

if __name__ == "__main__":
    
    main()