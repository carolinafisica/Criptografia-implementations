import os
import sys
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms

def setup(fkey):
    key = os.urandom(32)  # chacha20 usa chave de 256 bits
    with open(fkey, 'wb') as f:
        f.write(key)

def encrypt(fich, fkey):
    with open(fich, 'rb') as f:
        plaintext = f.read()
    with open(fkey, 'rb') as f:
        key = f.read()

    nonce = os.urandom(16)  # chacha20 usa nonce de 128 bits
    cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None)
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext)

    out_file = fich + '.enc'
    with open(out_file, 'wb') as f:
        f.write(nonce + ciphertext)  
 

def decrypt(fich, fkey):
    with open(fich, 'rb') as f:
        data = f.read()
    with open(fkey, 'rb') as f:
        key = f.read()

    nonce = data[:16]        # extrair os primeiros 16 bytes (nonce)
    ciphertext = data[16:]   # o restante é o criptograma

    cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None)
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext)

    out_file = fich + '.dec'
    with open(out_file, 'wb') as f:
        f.write(plaintext)

if __name__ == '__main__':

    cmd = sys.argv[1]

    if cmd == 'setup' and len(sys.argv) == 3:
        setup(sys.argv[2])
    elif cmd == 'enc' and len(sys.argv) == 4:
        encrypt(sys.argv[2], sys.argv[3])
    elif cmd == 'dec' and len(sys.argv) == 4:
        decrypt(sys.argv[2], sys.argv[3])

