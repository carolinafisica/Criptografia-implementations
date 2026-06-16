

import os
import random
from abc import ABC, abstractmethod
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding

# reutilizei as classes abstratas de indcpa.py

class AbstractCipher(ABC):

    @abstractmethod
    def keygen(self) -> bytes:
        pass

    @abstractmethod
    def enc(self, key: bytes, plaintext: bytes) -> bytes:
        pass

    @abstractmethod
    def dec(self, key: bytes, ciphertext: bytes) -> bytes:
        pass


class INDCPA_Adv(ABC):

    @abstractmethod
    def choose(self, oracle: callable) -> tuple[bytes, bytes]:
        pass

    @abstractmethod
    def guess(self, oracle: callable, ciphertext: bytes) -> int:
        pass




BLOCK_SIZE = 16  


def pad_pkcs7(data: bytes, block_size: int = BLOCK_SIZE) -> bytes:
    
    # Aplicar o padding PKCS#7 a data para o alinha ao block_size, modo ECB/CBC
    
    padder = sym_padding.PKCS7(block_size * 8).padder()
    return padder.update(data) + padder.finalize()


def unpad_pkcs7(data: bytes, block_size: int = BLOCK_SIZE) -> bytes:
    # Remove o padding 
    unpadder = sym_padding.PKCS7(block_size * 8).unpadder()
    return unpadder.update(data) + unpadder.finalize()


def xor_bytes(a: bytes, b: bytes) -> bytes:
    # XOR byte a byte entre dois arrays 
    return bytes(x ^ y for x, y in zip(a, b))


def IND_CPA(cipher: AbstractCipher, adversary: INDCPA_Adv) -> bool:
    # uma iteração do jogo IND-CPA.
  
    key        = cipher.keygen()
    enc_oracle = lambda plaintext: cipher.enc(key, plaintext)
    m0, m1     = adversary.choose(enc_oracle)
    assert len(m0) == len(m1)
    b          = random.randint(0, 1)
    c          = cipher.enc(key, m0 if b == 0 else m1)
    b_prime    = adversary.guess(enc_oracle, c)
    return b_prime == b


def run_experiment(
    cipher: AbstractCipher,
    adversary: INDCPA_Adv,
    trials: int = 1000
) -> None:
    
    wins      = sum(IND_CPA(cipher, adversary) for _ in range(trials))
    prob_win  = wins / trials
    advantage = 2 * abs(prob_win - 0.5)

    print(f"  vantagem    : {advantage:.4f}  ")
    


# ATAQUE 1, a insegurança no modelo IND do modo ECB (dois blocos)

# Estratégia do adversário:
#  m0 = block_A | block_B  (dois blocos distintos)
#  m1 = block_A | block_A  (dois blocos iguais)
#  Se o criptograma de c tem os dois blocos iguais então foi cifrado m1 (b=1)
#  caso contrario foi cifrado m0 (b=0)

class ECB_AES_Cipher(AbstractCipher):
    
    #Cifra AES no modo ECB

    #o mesmo bloco de texto gera sempre o mesmo bloco de criptograma, revelando padrões nas mensagens
    

    def keygen(self) -> bytes:
        return os.urandom(BLOCK_SIZE)

    def enc(self, key: bytes, plaintext: bytes) -> bytes:
        # padding para garantir que o tamanho é múltiplo de BLOCK_SIZE
        padded = pad_pkcs7(plaintext)
        cipher = Cipher(algorithms.AES(key), modes.ECB())
        encryptor = cipher.encryptor()
        return encryptor.update(padded) + encryptor.finalize()

    def dec(self, key: bytes, ciphertext: bytes) -> bytes:
        cipher = Cipher(algorithms.AES(key), modes.ECB())
        decryptor = cipher.decryptor()
        padded = decryptor.update(ciphertext) + decryptor.finalize()
        return unpad_pkcs7(padded)


class ECB_MultiBlock_Adversary(INDCPA_Adv):
    

    def __init__(self):
        self.block_A = b'AAAAAAAAAAAAAAAA' 
        self.block_B = b'BBBBBBBBBBBBBBBB' 

    def choose(self, oracle: callable) -> tuple[bytes, bytes]:
        m0 = self.block_A + self.block_B   
        m1 = self.block_A + self.block_A   
        return m0, m1

    def guess(self, oracle: callable, ciphertext: bytes) -> int:
        # O criptograma ECB de 2 blocos tem 32 bytes (sem padding extra aqui
        # pois 2 blocos de 16 bytes não precisam de padding)
        # verifica se se os dois blocos do criptograma são iguais
        bloco1 = ciphertext[:BLOCK_SIZE]
        bloco2 = ciphertext[BLOCK_SIZE:2*BLOCK_SIZE]

        if bloco1 == bloco2:
            return 1
        else:
            return 0


# ATAQUE 2 insegurança no modelo IND-CPA do modo ECB (bloco único)

# Estratégia do adversário:
# choose:  escolhe m0 e m1; consulta o oracle para cifrar m0 e guarda 
# guess:   compara c (criptograma de m_b) com c0:
# c == c0  entao o  b=0  (cifrou m0)
# caso contrario se c != c0 entao o  b=1  (cifrou m1)


class ECB_SingleBlock_Adversary(INDCPA_Adv):
 

    def __init__(self):
        self.c0 = None  # cifra de m0

    def choose(self, oracle: callable) -> tuple[bytes, bytes]:
        m0 = b'mensagem_zero!!!'  
        m1 = b'mensagem_um!!!!!'  

        # usa-se o oracle para cifrar m0 e guarda-se o resultado
        self.c0 = oracle(m0)

        return m0, m1

    def guess(self, oracle: callable, ciphertext: bytes) -> int:
        
        if ciphertext == self.c0:
            return 0  
        else:
            return 1 


# ATAQUE 3, a insegurança no modelo IND-CPA do ChaCha20 com nonce fixo


# Estratégia do adversário:
# choose:  cifra m0 via oracle e obtém c0 = m0 XOR ks
#          ks = c0 XOR m0  (pois m0 é conhecido)
# guess:   decifra c = m_b XOR ks e obtém m_b = c XOR ks
#          Compara m_b com m0, se igual b=0, se diferente b=1


class ChaCha20FixedNonce(AbstractCipher):


    NONCE = b'\x00' * 16  # nonce fixo
    def keygen(self) -> bytes:
        return os.urandom(32)  # chave aleatória de 256 bits

    def enc(self, key: bytes, plaintext: bytes) -> bytes:
        # a falha está aqui em usar sempre o mesmo nonce fixo 
        cipher = Cipher(algorithms.ChaCha20(key, self.NONCE), mode=None)
        encryptor = cipher.encryptor()
        return encryptor.update(plaintext)

    def dec(self, key: bytes, ciphertext: bytes) -> bytes:
        cipher = Cipher(algorithms.ChaCha20(key, self.NONCE), mode=None)
        decryptor = cipher.decryptor()
        return decryptor.update(ciphertext)


class FixedNonce_Adversary(INDCPA_Adv):
    
    # Adversário IND-CPA explora a reutilização do nonce no ChaCha20

    

    def __init__(self):
        self.m0        = None
        self.m1        = None
        self.keystream = None

    def choose(self, oracle: callable) -> tuple[bytes, bytes]:
        self.m0 = b'mensagem_ZERO!!!'   
        self.m1 = b'mensagem_UM!!!!!'   

        # Pede ao oracle a cifra de m0
        # Como nonce é fixo, c0 = m0 XOR ks
        c0 = oracle(self.m0)

        # Recupera a keystream = c0 XOR m0
        # (c0 XOR m0 = (m0 XOR ks) XOR m0 = ks)
        self.keystream = xor_bytes(c0, self.m0)

        return self.m0, self.m1

    def guess(self, oracle: callable, ciphertext: bytes) -> int:
        # Decifra o criptograma desafio usando a keystream recuperada
        # c = m_b XOR ks  entao m_b = c XOR ks
        recovered = xor_bytes(ciphertext, self.keystream)

        if recovered == self.m0:
            return 0  
        else:
            return 1  




if __name__ == '__main__':


    print("ATAQUE 1")
   
    run_experiment(
        cipher    = ECB_AES_Cipher(),
        adversary = ECB_MultiBlock_Adversary(),
        trials    = 1000
    )

 
    print("ATAQUE 2")


    run_experiment(
        cipher    = ECB_AES_Cipher(),
        adversary = ECB_SingleBlock_Adversary(),
        trials    = 1000
    )


    print("ATAQUE 3")

    run_experiment(
        cipher    = ChaCha20FixedNonce(),
        adversary = FixedNonce_Adversary(),
        trials    = 1000
    )

  