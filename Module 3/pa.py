from cryptography.hazmat.primitives import hashes 
from colorama import Fore,Style
import sys 
import os 


def load_video(video_name):
    video = open(video_name,'rb')
    return video.read()

def compute_hashes(video):
    video_size = os.path.getsize(video)
    block_size = 1024 
  
    f = open(video,'rb')

    
    last_block_size = video_size % block_size 
   

    f.seek(-last_block_size,2) # from -last_blocksize to the end 
    last_block = f.read()   # getting last block 
    video_size-= last_block_size
  
    digest = hashes.Hash(hashes.SHA256())
    digest.update(last_block) # hash last block 
    hashed = digest.finalize()

    
    while video_size > 0: 
        
        f.seek(video_size-block_size)
        block = f.read(block_size)
        
        digest = hashes.Hash(hashes.SHA256())
        digest.update(block+hashed)
        hashed = digest.finalize()
        
        video_size-=block_size

    
    return hashed

     

def main():

    video_name = '6.1.intro.mp4'

    check_video = '6.2.birthday.mp4'
    check_hash = '03c08f4ee0b576fe319338139c045c89c3e8e9409633bea29442e21425006ea8'


  
    if check_hash == compute_hashes(check_video).hex():
        print(f'Test {Fore.GREEN}PASSED{Style.RESET_ALL}')
    else: 
        print(f'Test {Fore.RED}FAILED{Style.RESET_ALL}')

    print(compute_hashes(video_name).hex())
    


if __name__ == '__main__':
    main() 