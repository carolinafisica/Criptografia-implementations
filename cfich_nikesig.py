"""
No cfich_nike.py, a Alice usa a chave pública do Bob
estabelecer a chave de sessão. Mas como é que eu sei que esse ficheiro é mesmo de Bob
e não foi substituído por um adversario? vou usar assinaturas RSA

O Bob vai ter de assinar a sua chave pública com a sua chave privada RSA
A Alice verifica essa assinatura com a chave pública RSA de Bob antes de usar o ficheiro


  setup <user>:
    1. Gera par de chaves:  user.dhsk  /  user.dhpk_raw
    2. Gera par RSA: user.rsask  /  user.rsapk
    3. o Bob assina a sua pk com rsask 
    4. Gravar user.dhpk = mkpair(dhpk_raw, sig)   que é a pk autenticada
    5. Gravar user.dhsk, user.rsask, user.rsapk

  enc <user> <me> <fich>   (Alice='me' envia para Bob='user')
    1. Lê user.dhpk → extrai dhpk_bob + sig; verifica sig com user.rsapk
       (garante que a chave DH de Bob é autêntica)
    2. Gera par DH temporário (skAlice, pkAlice) com params de Bob
    3. Calcula segredo partilhado K = DH(skAlice, pkBob)
    4. Deriva chave de sessão com HKDF
    5. SIGN-THEN-ENCRYPT:
       a. Assina o texto limpo com me.rsask  → sig_plaintext
       b. Empacota:  conteúdo = mkpair(sig_plaintext, plaintext)
       c. Cifra o conteúdo com ChaCha20-Poly1305
    6. Grava fich.enc = mkpair(pkAlice_bytes, nonce + criptograma)

  dec <me> <user> <fich>   (Bob='me' recebe de Alice='user')
    1. Lê me.dhsk → skBob
    2. Extrai pkAlice do ficheiro
    3. Calcula K = DH(skBob, pkAlice) → deriva chave de sessão
    4. Decifra → obtém mkpair(sig, plaintext)
    5. Verifica sig sobre plaintext com user.rsapk  ← autentica remetente
    6. Grava ficheiro .dec


"""

import os
import sys

from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.asymmetric.dh import (
    DHPrivateKey, DHPublicKey, DHParameters
)

from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey

# Serialização, de chaves para bytes e de bytes para chaves
from cryptography.hazmat.primitives.serialization import (
    Encoding, PublicFormat, PrivateFormat, NoEncryption,
    load_der_public_key, load_der_private_key
)

from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

# cifra autenticada 
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305


DH_P = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF
DH_G = 2
DH_PARAMS: DHParameters = dh.DHParameterNumbers(DH_P, DH_G).parameters()


# EMPACOTAR / DESEMPACOTAR PARES DE BYTE-STRINGS
# Necessário para guardar múltiplos valores de tamanho variável
# num único ficheiro binário

def mkpair(x: bytes, y: bytes) -> bytes:

    return len(x).to_bytes(2, 'big') + x + y


def unpair(xy: bytes) -> tuple[bytes, bytes]:
    len_x = int.from_bytes(xy[:2], 'big')
    return xy[2: len_x + 2], xy[len_x + 2:]


# DERIVAÇÃO DA CHAVE DE SESSÃO

def derive_session_key(shared_secret: bytes, length: int = 32) -> bytes:
    
   # Transforma o segredo DH em bytes uniformes  prontos a serem usados como chave de cifra
    
    return HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=None,
        info=b'cfich_nikesig_session_key',
    ).derive(shared_secret)


# ASSINATURA RSA (com padding PSS)

def rsa_sign(private_key: RSAPrivateKey, data: bytes) -> bytes:
  
      # permite que texto com a mesma chave não tenha assinaturas iguais 
      # o PSS adiciona aleatoriedade à assinatura RSA através de um salt, tornando-a probabilística e com prova de segurança formal
      # Antes de o RSA assinar, o PSS transforma a mensagem. ela passa pelo hash, depois isso passa por um salt e uma constante e dai resulta a RSA signature


    return private_key.sign(
        data,
        asym_padding.PSS(
            mgf=asym_padding.MGF1(hashes.SHA256()), #mascara: espalha o salt por toda a estrutura do padding
            salt_length=asym_padding.PSS.MAX_LENGTH #salt máximo que existe para ser prudente
        ),
        hashes.SHA256()
    )


def rsa_verify(public_key: RSAPublicKey, signature: bytes, data: bytes) -> bool:
    """
    Verifica a assinatura RSA sobre o data
    Devolve true se válida, false se inválida
    """
    try:
        public_key.verify(
            signature,
            data,
            asym_padding.PSS(
                mgf=asym_padding.MGF1(hashes.SHA256()),
                salt_length=asym_padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except:
        return False


# setup

def setup(user: str) -> None:
    """
    Gera os quatro ficheiros de chave para o user, nomeadamente :
    .dhsk   - chave privada DH
    .dhpk   -chave pública DH + assinatura RSA 
    .rsask  - chave privada RSA 
    .rsapk  - chave pública RSA 
    dhpk tem mesmo de ser assinado porque
    Qualquer pessoa que tenha  o .dhpk (pk + assinatura RSA) precisa de saber que é autêntica.
    o Bob assina a sua própria chave DH pública com a sua chave RSA privada.
    Quem tiver .rsapk e .dh.pk faço o rsa_verify
    Se um adversario substituir a chave pública DH do Bob por uma dele, a assinatura do Bob já não vai bater certo com os dados
    """

    #par de chaves DH
    dh_private: DHPrivateKey = DH_PARAMS.generate_private_key()
    dh_public:  DHPublicKey  = dh_private.public_key()

    dhsk_bytes = dh_private.private_bytes(
        encoding=Encoding.DER,
        format=PrivateFormat.PKCS8,
        encryption_algorithm=NoEncryption()
    )
    dhpk_bytes = dh_public.public_bytes(
        encoding=Encoding.DER,
        format=PublicFormat.SubjectPublicKeyInfo
    )

    # par de chaves RSA 
    # public_exponent=65537 é o valor standard e seguro
    rsa_private: RSAPrivateKey = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    rsa_public: RSAPublicKey = rsa_private.public_key()

    rsask_bytes = rsa_private.private_bytes(
        encoding=Encoding.DER,
        format=PrivateFormat.PKCS8,
        encryption_algorithm=NoEncryption()
    )
    rsapk_bytes = rsa_public.public_bytes(
        encoding=Encoding.DER,
        format=PublicFormat.SubjectPublicKeyInfo
    )

    #assinar a chave pública DH com a chave RSA privada
    sig_dhpk = rsa_sign(rsa_private, dhpk_bytes)

    # Gravar ficheiros
    with open(f'{user}.dhsk', 'wb') as f:
        f.write(dhsk_bytes)

    # dhpk contém o par (chave DH pública, assinatura) e vou juntar os dois usando o mkpair
    with open(f'{user}.dhpk', 'wb') as f:
        f.write(mkpair(dhpk_bytes, sig_dhpk))

    with open(f'{user}.rsask', 'wb') as f:
        f.write(rsask_bytes)

    with open(f'{user}.rsapk', 'wb') as f:
        f.write(rsapk_bytes)



# enc

def encrypt(dest: str, sender: str, fich: str) -> None:
    """
    Cifra o ficheiro 'fich' para o destinatário 'dest', assinado por 'sender'.

    primeiro verifica a autenticidade da chave DH de 'dest' (via RSA), depois gera um par DH temporário e calcula a chave de sessão
    terceiro, o SIGN-THEN-ENCRYPT (Assinar o texto limpo com a chave RSA privada do remetente e depois cifrar (assinatura + texto limpo) com ChaCha20-Poly1305)
    quarto, gravar: pkAlice || nonce || criptograma

    """

    # Ler e verificar a chave DH do destinatário
    # user.dhpk contém mkpair(dhpk_bytes, sig_dhpk)
    with open(f'{dest}.dhpk', 'rb') as f:
        dhpk_blob = f.read()

    dhpk_bytes, sig_dhpk = unpair(dhpk_blob)

    # Carregar a chave RSA pública do destinatário para verificar a assinatura
    with open(f'{dest}.rsapk', 'rb') as f:
        dest_rsa_pub: RSAPublicKey = load_der_public_key(f.read())

    # VERIFICAÇÃO se a assinatura sobre dhpk_bytes é válida?
    if not rsa_verify(dest_rsa_pub, sig_dhpk, dhpk_bytes):
        print(f" assinatura da chave DH inválida")
        sys.exit(1)

    print(f"assinatura DH verificada com sucesso")

    # Desserializar (transformar bytes num objeto python) a chave DH pública (agora confirmada como autêntica)
    pk_dest: DHPublicKey = load_der_public_key(dhpk_bytes)

    # gerar um par DH temporário (nao fica guardada num ficheiro) e calcular segredo partilhado
    # Para a Alice cifrar algo para o Bob sem falar com ele, ela "inventa" um par de chaves DH novo no momento
    # usa a chave privada desse par temporário para calcular o segredo com a chave pública do Bob
    # O par temporário usa os mesmos parâmetros DH da chave do destinatário
    params = pk_dest.parameters()
    sk_sender_dh: DHPrivateKey = params.generate_private_key()
    pk_sender_dh: DHPublicKey  = sk_sender_dh.public_key()

    # K = g^(skSender * skDest) mod p coisa que só a Alice e o Bob conseguem calcular
    shared_secret: bytes    = sk_sender_dh.exchange(pk_dest)
    session_key:   bytes    = derive_session_key(shared_secret)

    # Ler o texto limpo
    with open(fich, 'rb') as f:
        plaintext: bytes = f.read()

    #  assinar o texto limpo com a chave RSA privada do remetente 
    with open(f'{sender}.rsask', 'rb') as f:
        sender_rsa_priv: RSAPrivateKey = load_der_private_key(f.read(), password=None)

    sig_plaintext: bytes = rsa_sign(sender_rsa_priv, plaintext)

    # Empacotar (assinatura + texto limpo) para cifrar tudo junto
    signed_content: bytes = mkpair(sig_plaintext, plaintext)

    #cifrar o conteúdo assinado com ChaCha20-Poly1305
    chacha = ChaCha20Poly1305(session_key)
    nonce  = os.urandom(12)   # nonce aleatório de 96 bits
    ciphertext: bytes = chacha.encrypt(nonce, signed_content, None)

    #Serializar pkSender e montar o ficheiro final
    pk_sender_bytes = pk_sender_dh.public_bytes(
        encoding=Encoding.DER,
        format=PublicFormat.SubjectPublicKeyInfo
    )

    # Formato do ficheiro .enc:
    #   mkpair( pkAlice_DH , nonce(12 bytes) + criptograma )
    out_blob = mkpair(pk_sender_bytes, nonce + ciphertext)

    out_file = fich + '.enc'
    with open(out_file, 'wb') as f:
        f.write(out_blob)




# dec

def decrypt(me: str, sender: str, fich: str) -> None:
    """
    Decifra o ficheiro fich e verifica a assinatura do remetente 

    Passos:
      1. Ler chave privada DH de 'me'
      2. Extrair pkSender (DH) do ficheiro
      3. Calcular segredo partilhado → derivar chave de sessão
      4. Decifrar → obter (assinatura + texto limpo)
      5. VERIFICAR assinatura com chave RSA pública do 'sender'
      6. Gravar texto limpo

    me     : utilizador destinatário (ex: 'bob')   — precisa de <me>.dhsk
    sender : utilizador remetente (ex: 'alice')    — precisa de <sender>.rsapk
    fich   : ficheiro cifrado (com extensão .enc)
    """

    #Ler a chave privada DH do destinatário
    with open(f'{me}.dhsk', 'rb') as f:
        sk_me: DHPrivateKey = load_der_private_key(f.read(), password=None)

    # Ler o ficheiro cifrado e extrair componentes
    with open(fich, 'rb') as f:
        blob: bytes = f.read()

    # Extrair pkSender (DH) e o resto (nonce + criptograma)
    pk_sender_bytes, nonce_and_ct = unpair(blob)
    pk_sender: DHPublicKey = load_der_public_key(pk_sender_bytes)

    nonce      = nonce_and_ct[:12]
    ciphertext = nonce_and_ct[12:]

    # Calcular o segredo partilhado e derivar chave de sessão ---
    # DH(skBob, pkAlice) = g^(skBob * skAlice) = g^(skAlice * skBob) = DH(skAlice, pkBob)
    shared_secret: bytes = sk_me.exchange(pk_sender)
    session_key:   bytes = derive_session_key(shared_secret)

    # Decifrar
    chacha = ChaCha20Poly1305(session_key)
    try:
        signed_content: bytes = chacha.decrypt(nonce, ciphertext, None)
    except Exception:
        sys.exit(1)

    # Desempacotar (assinatura + texto limpo)
    sig_plaintext, plaintext = unpair(signed_content)

    # VERIFICAR a assinatura com a chave RSA pública do remetente
    # Se a assinatura for inválida, a mensagem não veio de 'sender'
    with open(f'{sender}.rsapk', 'rb') as f:
        sender_rsa_pub: RSAPublicKey = load_der_public_key(f.read())

    if not rsa_verify(sender_rsa_pub, sig_plaintext, plaintext):
        sys.exit(1)

    # gravar texto limpo 
    out_file = fich + '.dec'
    with open(out_file, 'wb') as f:
        f.write(plaintext)




if __name__ == '__main__':

    if len(sys.argv) < 3:
        print("Uso:")
        print("  python cfich_nikesig.py setup <user>")
        print("  python cfich_nikesig.py enc   <dest> <me> <fich>")
        print("  python cfich_nikesig.py dec   <me>   <sender> <fich>")
        sys.exit(1)

    cmd = sys.argv[1]

    if cmd == 'setup' and len(sys.argv) == 3:
        # setup bob -> gera bob.dhsk, bob.dhpk, bob.rsask, bob.rsapk
        setup(sys.argv[2])

    elif cmd == 'enc' and len(sys.argv) == 5:
        # enc bob alice ptxt.txt -> cifra para bob, assinado pela alice
        encrypt(dest=sys.argv[2], sender=sys.argv[3], fich=sys.argv[4])

    elif cmd == 'dec' and len(sys.argv) == 5:
        # dec bob alice ptxt.txt.enc -> bob decifra e verifica assinatura da alice
        decrypt(me=sys.argv[2], sender=sys.argv[3], fich=sys.argv[4])

    else:
        sys.exit(1)
