import os
import sys
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.exceptions import InvalidSignature


def derive_keys(passphrase: str, salt: bytes):
# deriva 64 bytes com PBKDF2, os primeiros 32 para AES-CTR cifra , últimos 32 para HMAC
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=64,           
        salt=salt,
        iterations=444444
    )
    key_material = kdf.derive(passphrase.encode()) #transformar a password em 64 bytes aleatórios
    enc_key = key_material[:32]
    mac_key = key_material[32:]
    return enc_key, mac_key


def encrypt(fich: str, passphrase: str):
    with open(fich, 'rb') as f:
        plaintext = f.read()

    salt  = os.urandom(16)  # para o PBKDF2

    nonce = os.urandom(16) # para AES-CTR
    enc_key, mac_key = derive_keys(passphrase, salt) # a password é transformada em duas chaves 

    # cifrar com o AES-CTR
    cipher = Cipher(algorithms.AES(enc_key), modes.CTR(nonce))
    ciphertext = cipher.encryptor().update(plaintext)

    # calcular o HMAC sobre o salt || nonce || ciphertext que é o tal encrypt-then-MAC
    h = hmac.HMAC(mac_key, hashes.SHA256())
    h.update(salt + nonce + ciphertext)
    tag = h.finalize()

    out = fich + '.enc'
    with open(out, 'wb') as f:
        f.write(salt + nonce + ciphertext + tag)



def decrypt(fich: str, passphrase: str):
    with open(fich, 'rb') as f:
        data = f.read()

    # desmontar as coisas : salt(16) + nonce(16) + ciphertext(n) + tag(32)
    salt       = data[:16]
    nonce      = data[16:32]
    tag        = data[-32:]
    ciphertext = data[32:-32]

    enc_key, mac_key = derive_keys(passphrase, salt)

    # deifrar com AES-CTR
    cipher = Cipher(algorithms.AES(enc_key), modes.CTR(nonce))
    plaintext = cipher.decryptor().update(ciphertext)

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

    
