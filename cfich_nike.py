
import os
import sys

from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.asymmetric.dh import (DHPrivateKey, DHPublicKey, DHParameters)


from cryptography.hazmat.primitives.serialization import ( #converter as coisas que usamos em Python em bytes ou ficheiro
    Encoding,             # formato binário ou texto 
    PublicFormat,         # formato para chaves públicas
    PrivateFormat,        # formato para chaves privadas
    NoEncryption,         # chave privada sem password 
    load_der_public_key,  # lê chave pública de bytes DER
    load_der_private_key  # lê chave privada de bytes DER
)

from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

# o g é um valor de p

DH_P = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF
DH_G = 2

# objeto de parâmetros DH a partir dos valores p e g que depois vai servir para gerar os pares de chaves
DH_PARAMS: DHParameters = dh.DHParameterNumbers(DH_P, DH_G).parameters()


# como precisamos de guardar num único ficheiro dois valores de tamanhos variáveis (pkAlice e o criptograma)
# Como vou saber onde acaba um e começa o outro?
# vou guardar primeiro o tamanho de pkAlice em 2 bytes, depois pkAlice, depois o resto

def mkpair(x: bytes, y: bytes) -> bytes:
    len_x = len(x)
    len_x_bytes = len_x.to_bytes(2)  #converter o tamanho para 2 bytes
    return len_x_bytes + x + y


def unpair(xy: bytes) -> tuple[bytes, bytes]: #Separa um pacote criado com mkpair de volta nos dois componentes pkAlice e criptograma

    len_x = int.from_bytes(xy[:2])   # tamanho de pkAlice
    x = xy[2 : len_x + 2]          
    y = xy[len_x + 2:]             
    return x, y


# DERIVAÇÃO DA CHAVE DE SESSÃO de tamanho fixo a partir do DH

def derive_session_key(shared_secret: bytes, length: int = 32) -> bytes:
    """
    deriva uma chave de sessão de tamanho fixo a partir do segredo DH
    O HKDF transforma o DH
    num array de bytes uniformemente distribuídos e do tamanho exato
    que se precisa (32 bytes para ChaCha20)

    # os shared_secret sao bytes resultantes do acordo DH
    # o length é o tamanho da chave de saída 
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=None,
        info=b'',
        
    )
    return hkdf.derive(shared_secret)


# OPERAÇÃO: setup

def setup(user: str) -> None:
    """
    gera um par de chaves para o user e
    grava-as em dois ficheiros
    como as chaves DH não são meros bytes, para os
    guardar em ficheiro uso serialização DER que é o formato binário compacto
    """

    private_key: DHPrivateKey = DH_PARAMS.generate_private_key()

    # Obter a chave pública a partir da privada
    public_key: DHPublicKey = private_key.public_key()

    # gravar a chave PRIVADA
    # PKCS8 é o formato standard 
    sk_bytes = private_key.private_bytes(
        encoding=Encoding.DER,          
        format=PrivateFormat.PKCS8,     
        encryption_algorithm=NoEncryption()
    )

    with open(f'{user}.sk', 'wb') as f:
        f.write(sk_bytes)

    # gravar a chave PÚBLICA 
    # SubjectPublicKeyInfo é o formato standard 
    pk_bytes = public_key.public_bytes(
        encoding=Encoding.DER,
        format=PublicFormat.SubjectPublicKeyInfo
    )

    with open(f'{user}.pk', 'wb') as f:
        f.write(pk_bytes)


# OPERAÇÃO: enc 

def encrypt(user: str, fich: str) -> None:

    # 1: ler a chave pública do destinatário 
    # load_der_public_key desserializa os bytes DER de volta a um objeto Python
    with open(f'{user}.pk', 'rb') as f:
        pk_bob: DHPublicKey = load_der_public_key(f.read())

    #2: gerar par de chaves para a Alice
    # que usa os mesmos parâmetros DH da chave do Bob
    # extraídos automaticamente da chave pública do Bob
    params_bob: DHParameters = pk_bob.parameters()
    sk_alice: DHPrivateKey  = params_bob.generate_private_key()
    pk_alice: DHPublicKey   = sk_alice.public_key()

    # 3: calcular o segredo partilhado 
    # exchange() realiza a operação DH que é a tal de computar g^(skAlice * skBob) mod p
    shared_secret: bytes = sk_alice.exchange(pk_bob)

    #  4: derivar a chave de sessão
    session_key: bytes = derive_session_key(shared_secret)

    # 5: Cifrar o ficheiro com ChaCha20-Poly1305
    with open(fich, 'rb') as f:
        plaintext: bytes = f.read()

    chacha = ChaCha20Poly1305(session_key)
    nonce = os.urandom(12)           # nonce de 96 bits (obrigatório para ChaCha20-Poly1305)
    ciphertext = chacha.encrypt(nonce, plaintext, None) # nounce + criptograma

    # 6: serializar pkAlice e gravar pkAlice no ficheiro para  o Bob poder calcular K
    pk_alice_bytes = pk_alice.public_bytes(
        encoding=Encoding.DER,
        format=PublicFormat.SubjectPublicKeyInfo
    )

    # mkpair junta pkAlice e (nonce + criptograma) num único pacote 
    # assim o Bob sabe  onde termina pkAlice e começa o criptograma
    encrypted_blob = mkpair(pk_alice_bytes, nonce + ciphertext)

    out_file = fich + '.enc'
    with open(out_file, 'wb') as f:
        f.write(encrypted_blob)

# OPERAÇÃO: dec (decifrar)

def decrypt(user: str, fich: str) -> None:

    # 1: ler a chave privada
    with open(f'{user}.sk', 'rb') as f:
        sk_bob: DHPrivateKey = load_der_private_key(f.read(), password=None)

    # 2: ler o criptograma e extrair os componentes
    with open(fich, 'rb') as f:
        blob: bytes = f.read()

    # unpair separa pkAlice do resto (nonce + criptograma)
    pk_alice_bytes, nonce_and_ct = unpair(blob)

    # pkAlice para um objeto Python DHPublicKey
    pk_alice: DHPublicKey = load_der_public_key(pk_alice_bytes)

    # separar o nonce (primeiros 12 bytes) do criptograma propriamente dito
    nonce      = nonce_and_ct[:12]
    ciphertext = nonce_and_ct[12:]

    # 3: calcular o segredo partilhado 
    shared_secret: bytes = sk_bob.exchange(pk_alice)

    # 4: Derivar a chave de sessão 
    session_key: bytes = derive_session_key(shared_secret)

    #5: Decifrar 
    chacha = ChaCha20Poly1305(session_key)

    plaintext: bytes = chacha.decrypt(nonce, ciphertext, None)

    out_file = fich + '.dec'
    with open(out_file, 'wb') as f:
        f.write(plaintext)



if __name__ == '__main__':

    cmd = sys.argv[1]

    if cmd == 'setup' and len(sys.argv) == 3:
        user = sys.argv[2]
        setup(user)

    elif cmd == 'enc' and len(sys.argv) == 4:
        user = sys.argv[2]
        fich = sys.argv[3]
        encrypt(user, fich)

    elif cmd == 'dec' and len(sys.argv) == 4:
        user = sys.argv[2]
        fich = sys.argv[3]
        decrypt(user, fich)

