import sys
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.exceptions import InvalidSignature


BLOCK_SIZE = 16

def cbc_mac_rnd_compute(key: bytes, message: bytes) -> tuple[bytes, bytes]:
    # Padding PKCS7
    padder = PKCS7(BLOCK_SIZE * 8).padder()
    padded = padder.update(message) + padder.finalize()

    # CBC com IV aleatório
    iv = os.urandom(BLOCK_SIZE)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()

    last_block = ciphertext[-BLOCK_SIZE:]
    return iv, last_block


def cmd_tag(key_file: str, data_file: str):
    with open(key_file, 'rb') as f:
        key = f.read()
    with open(data_file, 'rb') as f:
        message = f.read()

    iv, last_block = cbc_mac_rnd_compute(key, message)
    #tag = IV || último bloco de cifra
    tag = iv + last_block

    tag_file = data_file + '.tag'
    with open(tag_file, 'wb') as f:
        f.write(tag)



def cmd_verify(key_file: str, data_file: str, tag_file: str):
    with open(key_file, 'rb') as f:
        key = f.read()
    with open(data_file, 'rb') as f:
        message = f.read()
    with open(tag_file, 'rb') as f:
        stored_tag = f.read()

    # Extrair o iv e o last block do tag armazenado 
    stored_iv         = stored_tag[:BLOCK_SIZE]
    stored_last_block = stored_tag[BLOCK_SIZE:]

    # Padding PKCS7
    padder = PKCS7(BLOCK_SIZE * 8).padder()
    padded = padder.update(message) + padder.finalize()

    # Recompute com o IV armazenado
    cipher = Cipher(algorithms.AES(key), modes.CBC(stored_iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()
    computed_last_block = ciphertext[-BLOCK_SIZE:]



if __name__ == '__main__':

    cmd = sys.argv[1]

    if cmd == 'tag' and len(sys.argv) == 4:
        cmd_tag(sys.argv[2], sys.argv[3])
    elif cmd == 'verify' and len(sys.argv) == 5:
        cmd_verify(sys.argv[2], sys.argv[3], sys.argv[4])


# gerar uma chave AES de 16 bytes no terminal: python -c "import os; open('key.bin','wb').write(os.urandom(16))"