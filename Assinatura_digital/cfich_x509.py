"""


Extensão de cfich_nikesig.py que substitui os ficheiros .rsask/.rsapk
por certificados X.509 padrão. Os certificados estabelecem a autenticidade
das chaves públicas RSA de forma padronizada e verificável.

DIFERENÇAS FACE A cfich_nikesig.py
-------------------------------------
  Antes:  user.rsask / user.rsapk  (ficheiros gerados manualmente)
  Agora:  user.key   / user.crt    (chave privada RSA + certificado X.509)

  O certificado X.509 é emitido por uma Autoridade de Certificação (CA)
  e contém a chave pública RSA do utilizador + assinatura da CA.
  Para validar um certificado, verificamos que foi assinado pela CA.

VALIDAÇÃO DO CERTIFICADO (resumo)
-----------------------------------
Para cada certificado, verifica se:
  1. Período de validade (not_before ≤ agora ≤ not_after)
  2. Titular (subject) correcto (ex: COMMON_NAME == "ALICE")
  3. Assinatura da CA (verify_directly_issued_by)


Uso:
  python cfich_x509.py setup <user>
  python cfich_x509.py enc   <dest> <me> <fich>
  python cfich_x509.py dec   <me>   <sender> <fich>
"""

import os
import sys
import datetime
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.asymmetric.dh import DHPrivateKey, DHPublicKey, DHParameters
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.hazmat.primitives.serialization import (
    Encoding, PublicFormat, PrivateFormat, NoEncryption,
    load_pem_private_key,    # lê chave privada RSA de ficheiro PEM (formato .key)
     # O formato .key usado pelo OpenSSL é PEM (texto base64)
    load_der_public_key, load_der_private_key
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.exceptions import InvalidSignature


# PARÂMETROS DH FIXOS (RFC 3526, grupo 2048 bits)

DH_P = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF
DH_G = 2
DH_PARAMS: DHParameters = dh.DHParameterNumbers(DH_P, DH_G).parameters()


# =============================================================================
# EMPACOTAR / DESEMPACOTAR
# =============================================================================

def mkpair(x: bytes, y: bytes) -> bytes:
    return len(x).to_bytes(2, 'big') + x + y


def unpair(xy: bytes) -> tuple[bytes, bytes]:
    len_x = int.from_bytes(xy[:2], 'big')
    return xy[2: len_x + 2], xy[len_x + 2:]


# =============================================================================
# DERIVAÇÃO DA CHAVE DE SESSÃO
# =============================================================================

def derive_session_key(shared_secret: bytes, length: int = 32) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=None,
        info=b'cfich_x509_session_key',
    ).derive(shared_secret)


# =============================================================================
# ASSINATURA RSA COM PSS
# =============================================================================

def rsa_sign(private_key: RSAPrivateKey, data: bytes) -> bytes:
    return private_key.sign(
        data,
        asym_padding.PSS(
            mgf=asym_padding.MGF1(hashes.SHA256()),
            salt_length=asym_padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )


def rsa_verify(public_key: RSAPublicKey, signature: bytes, data: bytes) -> bool:
    """Verifica assinatura RSA-PSS. Devolve true se válida e false se não."""
    try:
        public_key.verify(
            signature, data,
            asym_padding.PSS(
                mgf=asym_padding.MGF1(hashes.SHA256()),
                salt_length=asym_padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except:
        return False


# =============================================================================
# CERTIFICADOS X.509 
# =============================================================================

def cert_load(fname: str) -> x509.Certificate:
    """Lê um certificado X.509 no formato PEM de um ficheiro."""
    with open(fname, "rb") as f:
        return x509.load_pem_x509_certificate(f.read())


def cert_validtime(cert: x509.Certificate) -> None:
    """
    Verifica que o certificado está dentro do seu período de validade.

    """
    now = datetime.datetime.now(tz=datetime.timezone.utc)
    if now < cert.not_valid_before_utc or now > cert.not_valid_after_utc:
        raise x509.verification.VerificationError(
            "Certificado fora do período de validade"
        )


def cert_validsubject(cert: x509.Certificate, attrs: list) -> None:
    """
    Verifica atributos do campo subject do certificado.
    'attrs' é uma lista de pares (x509.NameOID.COMMON_NAME, nome_esperado).
    """
    for oid, expected in attrs:
        actual = cert.subject.get_attributes_for_oid(oid)[0].value
        if actual != expected:
            raise x509.verification.VerificationError(
                f"Atributo {oid} do certificado: esperado '{expected}', obtido '{actual}'"
            )


def validate_cert(cert: x509.Certificate, ca_cert: x509.Certificate,
                  expected_cn: str) -> None:

    # 1. Verificar que a CA assinou este certificado
    cert.verify_directly_issued_by(ca_cert)

    # 2. Verificar período de validade
    cert_validtime(cert)

    # 3. Verificar a identidade. O CN pode ser "CSI ALICE" para o user "alice"
    #    por isso decidi fazer uma verificação para ver se o CN contém o nome simplesmente 
    cn = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
    if expected_cn.upper() not in cn.upper():
        raise x509.verification.VerificationError(
            f"COMMON_NAME '{cn}' não corresponde ao utilizador '{expected_cn}'"
        )


def load_private_key(fname: str, password: bytes = b"1234") -> RSAPrivateKey:
    """
    Lê a chave privada RSA de um ficheiro PEM protegido por password
    """
    with open(fname, "rb") as f:
        return load_pem_private_key(f.read(), password=password)


# =============================================================================
# Q1 -- Verificar que .key e .crt formam um par RSA válido
# =============================================================================

def check_keypair(cert_file: str, key_file: str, password: bytes = b"1234") -> bool:
    """
    Resposta à Q1: verifica que a chave privada e o certificado formam um par RSA válido.

    extraí a chave pública do certificado e deriva a chave pública
    da chave privada. Se os bytes DER de ambas forem iguais, é um par válido.

    Alternativa equivalente: assinar algo com a chave privada e verificar
    com a chave pública do certificado.
    """
    cert = cert_load(cert_file)
    private_key: RSAPrivateKey = load_private_key(key_file, password)

    # Chave pública do certificado
    pub_from_cert = cert.public_key().public_bytes(
        Encoding.DER, PublicFormat.SubjectPublicKeyInfo
    )

    # Chave pública derivada da chave privada
    pub_from_key = private_key.public_key().public_bytes(
        Encoding.DER, PublicFormat.SubjectPublicKeyInfo
    )

    return pub_from_cert == pub_from_key


# =============================================================================
# OPERAÇÃO: setup
# =============================================================================

def setup(user: str) -> None:
    """
    Gera o par de chaves DH para 'user' e assina a chave DH pública com
    a chave RSA privada do utilizador (retirada do ficheiro <user>.key).

    Grava:
      <user>.dhsk  -- chave privada DH (secreta)
      <user>.dhpk  -- chave pública DH + assinatura RSA (mkpair)

    A password da chave privada é b"1234".
    """

    # Carregar e validar o certificado do user contra a CA
    ca_cert = cert_load("CA.crt")
    user_cert = cert_load(f"{user}.crt")
    validate_cert(user_cert, ca_cert, user.upper())
    print(f"[setup] Certificado de '{user}' validado")

    # Carregar a chave privada RSA do user (para assinar a dhpk)
    user_rsa_priv: RSAPrivateKey = load_private_key(f"{user}.key")

    # Gerar par de chaves DH
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

    # Assinar a chave pública DH com a chave RSA privada do user
    # Qualquer pessoa com <user>.crt pode depois verificar que a dhpk é autêntica
    sig_dhpk = rsa_sign(user_rsa_priv, dhpk_bytes)

    # Gravar chave DH privada
    with open(f'{user}.dhsk', 'wb') as f:
        f.write(dhsk_bytes)

    # Gravar chave DH pública + assinatura RSA num único ficheiro
    with open(f'{user}.dhpk', 'wb') as f:
        f.write(mkpair(dhpk_bytes, sig_dhpk))

    print(f"[setup] Par de chaves DH gerado para '{user}':")
    print(f"  {user}.dhsk  -- chave privada DH")
    print(f"  {user}.dhpk  -- chave pública DH + assinatura RSA do certificado")


# =============================================================================
def encrypt(dest: str, sender: str, fich: str) -> None:
    """
    Cifra o ficheiro fich para o destinatário dest, assinado por sender

    Formato do payload cifrado:
      mkpair( cert_alice_pem , mkpair( sig_do_plaintext , plaintext ) )

   o Bob obtém o certificado da Alice diretamente do ficheiro .enc
    e não precisa de ter alice.crt localmente

    Formato do ficheiro .enc:
      mkpair( pk_alice_dh_efémera , nonce(12B) + ciphertext )
    """

    # --- 1: Validar certificados contra a CA ---

    # Para garantir que a chave pública no .dhpk é realmente de 'dest'.
    #   A CA emitiu o cert de Bob, por isso a sua chave RSA no cert é autêntica.
    #   Usa se essa chave RSA para verificar a assinatura na .dhpk.
    #   Sem validar o cert, não se tem base para confiar na chave RSA usada.
 
    ca_cert = cert_load("CA.crt")

    dest_cert = cert_load(f"{dest}.crt")
    validate_cert(dest_cert, ca_cert, dest.upper())

    sender_cert = cert_load(f"{sender}.crt")
    validate_cert(sender_cert, ca_cert, sender.upper())

    # --- 2: Ler e verificar a chave DH do destinatário ---
    # <dest>.dhpk = mkpair(dhpk_bytes, sig)
    # A sig foi feita por Bob com a sua chave RSA privada.
    # Verific-se com a chave pública do certificado de Bob, validado no passo 1
    with open(f'{dest}.dhpk', 'rb') as f:
        dhpk_blob = f.read()

    dhpk_bytes, sig_dhpk = unpair(dhpk_blob)
    dest_rsa_pub: RSAPublicKey = dest_cert.public_key()

    if not rsa_verify(dest_rsa_pub, sig_dhpk, dhpk_bytes):
        sys.exit(1)

    pk_dest: DHPublicKey = load_der_public_key(dhpk_bytes)

    # --- 3: Gerar par DH efémero (criado apenas para este ficheiro, não guardado) ---
    params = pk_dest.parameters()
    sk_sender_dh: DHPrivateKey = params.generate_private_key()
    pk_sender_dh: DHPublicKey  = sk_sender_dh.public_key()

    shared_secret: bytes = sk_sender_dh.exchange(pk_dest)
    session_key:   bytes = derive_session_key(shared_secret)

    # --- 4a: Ler o texto limpo e ASSINAR (SIGN) ---
    with open(fich, 'rb') as f:
        plaintext: bytes = f.read()

    sender_rsa_priv: RSAPrivateKey = load_private_key(f"{sender}.key")
    sig_plaintext: bytes = rsa_sign(sender_rsa_priv, plaintext)

    # --- 4b: CIFRAR com ChaCha20-Poly1305 ---
    # O payload cifrado contém apenas: mkpair(sig_plaintext, plaintext)
    # O cert da Alice vai para o exterior  -- passo 5
    signed_content: bytes = mkpair(sig_plaintext, plaintext)

    chacha = ChaCha20Poly1305(session_key)
    nonce  = os.urandom(12)
    ciphertext: bytes = chacha.encrypt(nonce, signed_content, None)

    # --- 5: Montar ficheiro final ---
    pk_sender_bytes = pk_sender_dh.public_bytes(
        encoding=Encoding.DER,
        format=PublicFormat.SubjectPublicKeyInfo
    )
    sender_cert_pem: bytes = sender_cert.public_bytes(Encoding.PEM)

    # Estrutura do ficheiro .enc (tudo em claro excepto ciphertext):
    #
    #   mkpair(
    #     pk_alice_dh_efemera,          #Bob usa para calcular K
    #     mkpair(
    #       cert_alice_pem,             #Bob sabe quem enviou ANTES de decifrar
    #       nonce + ciphertext          #conteudo cifrado: mkpair(sig, plaintext)
    #     )
    #   )
    inner_outer: bytes = mkpair(sender_cert_pem, nonce + ciphertext)
    out_blob:    bytes = mkpair(pk_sender_bytes, inner_outer)

    out_file = fich + '.enc'
    with open(out_file, 'wb') as f:
        f.write(out_blob)

    print(f"[enc] '{fich}' cifrado e assinado em {out_file}")


# =============================================================================
# OPERAÇÃO: dec
# =============================================================================

def decrypt(me: str, sender: str, fich: str) -> None:
    """
    Decifra o ficheiro 'fich' e verifica a assinatura do remetente 'sender'.

    Passos:
      1. Carregar chave DH privada de 'me' e calcular chave de sessão
      2. Decifrar, obtendo mkpair( cert_alice_pem , mkpair( sig , plaintext ) )
      3. Extrair e VALIDAR o certificado de Alice (emitido pela CA?)
      4. Verificar que o CN do cert corresponde ao 'sender' esperado
      5. Verificar assinatura RSA sobre o plaintext
      6. Gravar texto limpo
    """

    ca_cert = cert_load("CA.crt")

    # --- 1: Ler ficheiro e extrair componentes externos ---
    with open(fich, 'rb') as f:
        blob: bytes = f.read()

    # Estrutura exterior:
    #   mkpair( pk_alice_dh_efemera , mkpair( cert_alice_pem , nonce + ciphertext ) )
    pk_sender_bytes, inner_outer = unpair(blob)
    sender_cert_pem, nonce_and_ct = unpair(inner_outer)

    # --- 2: Validar o certificado da Alice ANTES de decifrar ---
    # O cert está em claro no ficheiro por isso o Bob sabe quem enviou mesmo sem decifrar.
    try:
        sender_cert = x509.load_pem_x509_certificate(sender_cert_pem)
    except Exception:
        sys.exit(1)

    try:
        validate_cert(sender_cert, ca_cert, sender.upper())
    except Exception as e:
        sys.exit(1)

    print(f"[dec] Certificado do remetente validado (emitido pela CA).")

    # --- 3: Carregar chave DH privada e derivar chave de sessao ---
    with open(f'{me}.dhsk', 'rb') as f:
        sk_me: DHPrivateKey = load_der_private_key(f.read(), password=None)

    pk_sender_dh: DHPublicKey = load_der_public_key(pk_sender_bytes)

    nonce      = nonce_and_ct[:12]
    ciphertext = nonce_and_ct[12:]

    # DH(skBob, pkAlice_efemera) -- mesmo segredo que Alice calculou
    shared_secret: bytes = sk_me.exchange(pk_sender_dh)
    session_key:   bytes = derive_session_key(shared_secret)

    # --- 4: Decifrar ---
    chacha = ChaCha20Poly1305(session_key)
    try:
        signed_content: bytes = chacha.decrypt(nonce, ciphertext, None)
    except Exception:
        sys.exit(1)

    # Payload decifrado = mkpair(sig_plaintext, plaintext)
    sig_plaintext, plaintext = unpair(signed_content)

    # --- 5: Verificar assinatura RSA sobre o plaintext ---
    # Usar a chave publica do certificado da Alice (ja validado no passo 2)
    sender_rsa_pub: RSAPublicKey = sender_cert.public_key()

    if not rsa_verify(sender_rsa_pub, sig_plaintext, plaintext):
        sys.exit(1)

    print(f"[dec] Assinatura de '{sender}' verificada com sucesso.")

    # --- 6: Gravar texto limpo ---
    out_file = fich + '.dec'
    with open(out_file, 'wb') as f:
        f.write(plaintext)

    print(f"[dec] Mensagem decifrada: {out_file}")



# =============================================================================
# PONTO DE ENTRADA
# =============================================================================

if __name__ == '__main__':

    # Q1: verificar par chave/certificado (executar com: python cfich_x509.py check <user>)
    if len(sys.argv) == 3 and sys.argv[1] == 'check':
        user = sys.argv[2]
        valid = check_keypair(f"{user}.crt", f"{user}.key")
        print(f"[Q1] {user}.crt + {user}.key formam par RSA válido: {valid}")
        sys.exit(0)


    cmd = sys.argv[1]

    if cmd == 'setup' and len(sys.argv) == 3:
        setup(sys.argv[2])

    elif cmd == 'enc' and len(sys.argv) == 5:
        encrypt(dest=sys.argv[2], sender=sys.argv[3], fich=sys.argv[4])

    elif cmd == 'dec' and len(sys.argv) == 5:
        decrypt(me=sys.argv[2], sender=sys.argv[3], fich=sys.argv[4])

    else:
        sys.exit(1)
