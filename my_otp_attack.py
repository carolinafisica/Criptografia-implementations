import sys
import random

def attack(enc_file, keywords):
    with open(enc_file, 'rb') as f:
        ciphertext = f.read()

    for seed in range(2**16): # pois em my_otp, é usado os.urandom(16)
        random.seed(seed)
        key = random.randbytes(len(ciphertext))
        plaintext = bytes(c ^ k for c, k in zip(ciphertext, key))
        
        
        text = plaintext.decode('utf-16', errors='ignore')

        if all(kw in text for kw in keywords):
            print(text, end='')
            return

if __name__ == '__main__':
    attack(sys.argv[1], sys.argv[2:])
