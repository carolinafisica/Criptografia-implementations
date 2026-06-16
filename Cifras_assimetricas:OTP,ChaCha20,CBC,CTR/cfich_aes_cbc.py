import os, sys
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

def setup(fkey):
    with open(fkey, 'wb') as f:
        f.write(os.urandom(32))  # AES-256


def encrypt(fich, fkey):
    with open(fich, 'rb') as f:
        plaintext = f.read()
    with open(fkey, 'rb') as f:
        key = f.read()

    iv = os.urandom(16)
    padder = padding.PKCS7(128).padder() #encher o ultimo bloco se não for multiplo de 16 bytes
    padded = padder.update(plaintext) + padder.finalize()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    ct = cipher.encryptor().update(padded)

    with open(fich + '.enc', 'wb') as f:
        f.write(iv + ct)
   

def decrypt(fich, fkey):
    with open(fich, 'rb') as f:
        data = f.read()
    with open(fkey, 'rb') as f:
        key = f.read()

    iv, ct = data[:16], data[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    padded = cipher.decryptor().update(ct)

    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded) + unpadder.finalize()

    with open(fich + '.dec', 'wb') as f:
        f.write(plaintext)

if __name__ == '__main__':
    cmd = sys.argv[1]
    if cmd == 'setup':   setup(sys.argv[2])
    elif cmd == 'enc':   encrypt(sys.argv[2], sys.argv[3])
    elif cmd == 'dec':   decrypt(sys.argv[2], sys.argv[3])
