"""
Este programa implementa a assinatura digital de ficheiros usando X.509.
Ao contrário da cifra (cfich_x509.py), aqui o objetivo é apenas garantir
AUTENTICIDADE e INTEGRIDADE, ou seja, qualquer um pode ler o ficheiro, mas só o
titular do certificado pode assiná-lo.

"""

import sys
import datetime

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.hazmat.primitives.serialization import (
    Encoding, load_pem_private_key
)
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature


# =============================================================================
# EMPACOTAR / DESEMPACOTAR
# =============================================================================

def mkpair(x: bytes, y: bytes) -> bytes:
    return len(x).to_bytes(2, 'big') + x + y


def unpair(xy: bytes) -> tuple[bytes, bytes]:
    len_x = int.from_bytes(xy[:2], 'big')
    return xy[2: len_x + 2], xy[len_x + 2:]


# =============================================================================
# ASSINATURA RSA-PSS
# =============================================================================

def rsa_sign(private_key: RSAPrivateKey, data: bytes) -> bytes:
    """Assina 'data' com PSS (salt aleatorio )"""
    return private_key.sign(
        data,
        asym_padding.PSS(
            mgf=asym_padding.MGF1(hashes.SHA256()),
            salt_length=asym_padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )


def rsa_verify_sig(public_key: RSAPublicKey, signature: bytes, data: bytes) -> bool:
    """Verifica assinatura RSA-PSS. Devolve True se válida."""
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
    except InvalidSignature:
        return False


# =============================================================================
# CERTIFICADOS X.509 
# =============================================================================

def cert_load_pem(fname: str) -> x509.Certificate:
    """Lê um certificado X.509 PEM de um ficheiro."""
    with open(fname, "rb") as f:
        return x509.load_pem_x509_certificate(f.read())


def cert_load_pem_bytes(data: bytes) -> x509.Certificate:
    """Lê um certificado X.509 PEM de bytes (extraído de .sig)."""
    return x509.load_pem_x509_certificate(data)


def validate_cert(cert: x509.Certificate, ca_cert: x509.Certificate) -> str:
    """
    Valida um certificado end-entity assim como pertence a quem deve.
    Verifica:
      1. Assinatura da CA 
      2. Período de validade
      3. Que não é um certificado de CA (Basic Constraints: cA=False)

    Devolve o COMMON_NAME do titular se válido.
    """

    # 1. Verificar assinatura da CA sobre este certificado
    #    (prova que a CA reconheceu e assinou este certificado)
    try:
        cert.verify_directly_issued_by(ca_cert)
    except Exception:
        raise ValueError(
        )

    # 2. Verificar período de validade
    now = datetime.datetime.now(tz=datetime.timezone.utc)
    if now < cert.not_valid_before_utc:
        raise ValueError(
        )
    if now > cert.not_valid_after_utc:
        raise ValueError(
        )

    # 3. Verificar que não é um certificado de CA; garantir que só certificados de utilizadores finais são aceites para assinar ficheiros e bao intermédios
    #    (um utilizador normal não deve ter cA=True nas Basic Constraints)
    try:
        bc = cert.extensions.get_extension_for_oid(
            x509.ExtensionOID.BASIC_CONSTRAINTS
        ).value
        if bc.ca:
            raise ValueError(
            )
    except x509.ExtensionNotFound:
        pass   # sem Basic Constraints, assumir end-entity 

    # Devolver o COMMON_NAME do titular (exibir ao utilizador)
    cn = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
    return cn[0].value if cn else "(sem COMMON_NAME)"


def print_cert_summary(cert: x509.Certificate, label: str = "") -> None:
    """Mostra um resumo dos campos mais importantes do certificado."""
    prefix = f"[{label}] " if label else ""
    cn_list = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
    cn = cn_list[0].value if cn_list else "?"
    issuer_cn_list = cert.issuer.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
    issuer_cn = issuer_cn_list[0].value if issuer_cn_list else "?"
    print(f"{prefix}Titular (Subject CN): {cn}")
    print(f"{prefix}Emitido por (Issuer CN): {issuer_cn}")
    print(f"{prefix}Válido de: {cert.not_valid_before_utc.date()}")
    print(f"{prefix}Válido até: {cert.not_valid_after_utc.date()}")
    print(f"{prefix}Chave pública: RSA {cert.public_key().key_size} bits")


# =============================================================================
# OPERAÇÃO: sign
# =============================================================================

def sign_file(user: str, fich: str) -> None:
    """
    Assina o ficheiro 'fich' com a chave privada de 'user' e grava <fich>.sig.

    O ficheiro .sig contém:
      mkpair( certificado PEM do utilizador , assinatura RSA-PSS )

    O certificado é incluído no .sig para que o verificador saiba quem assinou
    e possa obter a chave pública sem precisar de acesso prévio ao ficheiro do user.

    """

    # 1. Carregar e validar o certificado do utilizador
    ca_cert   = cert_load_pem("CA.crt")
    user_cert = cert_load_pem(f"{user}.crt")

    try:
        cn = validate_cert(user_cert, ca_cert)
    except ValueError as e:
        sys.exit(1)

    print(f"[sign] Certificado de '{user}' válido (titular: {cn})")
    print_cert_summary(user_cert, "sign")

    # 2. Carregar chave privada RSA (password padrão: b"1234")
    with open(f"{user}.key", "rb") as f:
        private_key: RSAPrivateKey = load_pem_private_key(f.read(), password=b"1234")

    # 3. Ler o conteúdo do ficheiro e assinar
    with open(fich, "rb") as f:
        content: bytes = f.read()

    signature: bytes = rsa_sign(private_key, content)

    # 4. Gravar ficheiro .sig = mkpair(cert_pem, assinatura)
    #    Incluí o certificado PEM completo para que o verificador
    #    possa identificar o signatário e obter a chave pública.
    cert_pem: bytes = user_cert.public_bytes(Encoding.PEM)

    sig_file = fich + ".sig"
    with open(sig_file, "wb") as f:
        f.write(mkpair(cert_pem, signature))

    print(f"[sign] Ficheiro '{fich}' assinado por '{cn}'.")
    print(f"[sign] Assinatura gravada em: {sig_file}")


# =============================================================================
# OPERAÇÃO: verify
# =============================================================================

def verify_file(fich: str) -> None:
    """
    Verifica a assinatura digital do ficheiro 'fich'.

    Pressupõe que existe <fich>.sig com mkpair(cert_pem, assinatura).

    """

    sig_file = fich + ".sig"

    with open(sig_file, "rb") as f:
        blob: bytes = f.read()

    # Extrair certificado PEM e assinatura
    cert_pem, signature = unpair(blob)

    # 1. Carregar o certificado do signatário (incluído no .sig)
    try:
        signer_cert = cert_load_pem_bytes(cert_pem)
    except Exception as e:
        sys.exit(1)

    # 2. Carregar CA e validar o certificado do signatário
    ca_cert = cert_load_pem("CA.crt")

    try:
        cn = validate_cert(signer_cert, ca_cert)
    except ValueError as e:
        print_cert_summary(signer_cert, "cert")
        sys.exit(1)

    print(f"[verify] Certificado do signatário válido (titular: {cn})")
    print_cert_summary(signer_cert, "verify")

    # 3. Extrair chave pública RSA do certificado
    signer_pub: RSAPublicKey = signer_cert.public_key()

    with open(fich, 'rb') as f:
        content: bytes = f.read()

    # 5. Verificar
    if rsa_verify_sig(signer_pub, signature, content):
        print(f"[verify] ASSINATURA VALIDA")
        print(f"[verify]   Ficheiro '{fich}' foi assinado por '{cn}'")
    else:
        print(f"[verify] ASSINATURA INVALIDA")

        sys.exit(1)


# =============================================================================
# PONTO DE ENTRADA
# =============================================================================

if __name__ == '__main__':

    if len(sys.argv) < 3:

        sys.exit(1)

    cmd = sys.argv[1]

    if cmd == 'sign' and len(sys.argv) == 4:
        # sign alice ptxt.txt : assina ptxt.txt com ALICE.key/ALICE.crt
        sign_file(user=sys.argv[2], fich=sys.argv[3])

    elif cmd == 'verify' and len(sys.argv) == 3:
        # verify ptxt.txt : verifica ptxt.txt contra ptxt.txt.sig
        verify_file(fich=sys.argv[2])

    else:
        sys.exit(1)
