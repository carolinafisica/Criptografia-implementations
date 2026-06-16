import os, sys
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def setup(fkey):
    with open(fkey, 'wb') as f:
        f.write(os.urandom(32))
 

def encrypt(fich, fkey):
    with open(fich, 'rb') as f:
        plaintext = f.read()
    with open(fkey, 'rb') as f:
        key = f.read()

    nonce = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce))
    ct = cipher.encryptor().update(plaintext)

    with open(fich + '.enc', 'wb') as f:
        f.write(nonce + ct)

def decrypt(fich, fkey):
    with open(fich, 'rb') as f:
        data = f.read()
    with open(fkey, 'rb') as f:
        key = f.read()

    nonce, ct = data[:16], data[16:]
    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce))
    plaintext = cipher.decryptor().update(ct)

    with open(fich + '.dec', 'wb') as f:
        f.write(plaintext)

if __name__ == '__main__':
    cmd = sys.argv[1]
    if cmd == 'setup':   setup(sys.argv[2])
    elif cmd == 'enc':   encrypt(sys.argv[2], sys.argv[3])
    elif cmd == 'dec':   decrypt(sys.argv[2], sys.argv[3])
