import os
import sys
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.exceptions import InvalidTag


def derive_key(passphrase: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=444444,
    )
    return kdf.derive(passphrase.encode())


def encrypt(fich: str, passphrase: str):
    with open(fich, 'rb') as f:
        plaintext = f.read()

    salt  = os.urandom(16)
    nonce = os.urandom(12)   # ChaCha20 usa nonce de 96 bits , ou seja 12 bytes
    key   = derive_key(passphrase, salt)

    chacha = ChaCha20Poly1305(key)
#o encrypt() devolve o ciphertext + tag concatenados
    ciphertext_with_tag = chacha.encrypt(nonce, plaintext, None)

    out = fich + '.enc'
    with open(out, 'wb') as f:
        f.write(salt + nonce + ciphertext_with_tag)



def decrypt(fich: str, passphrase: str):
    with open(fich, 'rb') as f:
        data = f.read()

    salt = data[:16]
    nonce = data[16:28]
    ciphertext_with_tag = data[28:]

    key = derive_key(passphrase, salt)

    chacha = ChaCha20Poly1305(key)
   
    plaintext = chacha.decrypt(nonce, ciphertext_with_tag, None)


    out = fich + '.dec'
    with open(out, 'wb') as f:
        f.write(plaintext)


if __name__ == '__main__':

    cmd        = sys.argv[1]
    ficheiro   = sys.argv[2]
    passphrase = sys.argv[3]

    if cmd == 'enc':
        encrypt(ficheiro, passphrase)
    elif cmd == 'dec':
        decrypt(ficheiro, passphrase)

