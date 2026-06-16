

import os
import random
from abc import ABC, abstractmethod
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms


class AbstractCipher(ABC):


    @abstractmethod
    def keygen(self) -> bytes:
        #gerar e devolver uma chave para a cifra
        pass

    @abstractmethod
    def enc(self, key: bytes, plaintext: bytes) -> bytes:
        
        # Cifra o plaintext com a key e devolve o criptograma
        # o criptograma pode incluir dados auxiliares tipo o nonce no início
        
        pass

    @abstractmethod
    def dec(self, key: bytes, ciphertext: bytes) -> bytes:
        
        #decifra o ciphertext com a key e devolve o texto limpo original
        
        pass


class INDCPA_Adv(ABC):
 

      # 1. choose onde o adversário escolhe dois textos limpos m0 e m1
      # do mesmo tamanho. pode consultar o oracle (pedir cifras) antes
      # 2. guess onde o adversário recebe o criptograma de m_b 
      # e tenta adivinhar qual das duas mensagens foi cifrada, com a 
      # estimativa de b entre 0 e 1
    

    @abstractmethod
    def choose(self, oracle: callable) -> tuple[bytes, bytes]:
        
        pass

    @abstractmethod
    def guess(self, oracle: callable, ciphertext: bytes) -> int:
      
        pass




class IdentityCipher(AbstractCipher):
    
    #Cifra identidade: enc(k, m) = m  e  dec(k, c) = c.

    # o criptograma é igual ao texto limpo
    
    

    def keygen(self) -> bytes:
        # não é necessária nenhuma chave; devolvemos bytes vazios
        return b''

    def enc(self, key: bytes, plaintext: bytes) -> bytes:
        # Cifra não faz nada, devolve o texto tal e qual
        return plaintext

    def dec(self, key: bytes, ciphertext: bytes) -> bytes:
        # Decifra não faz nada, o criptograma já é o texto limpo
        return ciphertext


class IdentityAdversary(INDCPA_Adv):
   
      # choose: escolhe duas mensagens diferehtes m0 e m1.
      # guess:  como enc(k, m) = m, o criptograma é  m_b.
      #basta comparar c com m0. Se iguais, b=0; se nao, b=1.

    # Este adversário ganha sempre 
    

    def __init__(self):
       
        self.m0 = None
        self.m1 = None

    def choose(self, oracle: callable) -> tuple[bytes, bytes]:
        self.m0 = b'mensagem_zero_!!!'  
        self.m1 = b'mensagem_um_!!!!!' 
        return self.m0, self.m1

    def guess(self, oracle: callable, ciphertext: bytes) -> int:
        # na cifra identidade o criptograma == texto limpo.
        # Se o que recebemos é igual a m0, então b=0; senão b=1.
        if ciphertext == self.m0:
            return 0
        else:
            return 1




class ChaCha20Cipher(AbstractCipher):


    NONCE_SIZE = 16  

    def keygen(self) -> bytes:
        # gerar uma chave aleatória de 256 bits (32 bytes)
        return os.urandom(32)

    def enc(self, key: bytes, plaintext: bytes) -> bytes:
        # gerar um nonce aleatório para cada cifra
        nonce = os.urandom(self.NONCE_SIZE)
        cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None)
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext)
        # concatenar nonce + ciphertext para que o dec possa recuperar o nonce
        return nonce + ciphertext

    def dec(self, key: bytes, ciphertext: bytes) -> bytes:
        # separar o nonce (primeiros 16 bytes) do criptograma real
        nonce     = ciphertext[:self.NONCE_SIZE]
        enc_data  = ciphertext[self.NONCE_SIZE:]
        cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None)
        decryptor = cipher.decryptor()
        return decryptor.update(enc_data)


class RandomAdversary(INDCPA_Adv):

    def choose(self, oracle: callable) -> tuple[bytes, bytes]:
        # escolher duas mensagens de tamanho fixo
        self.m0 = b'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' 
        self.m1 = b'BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB' 
        return self.m0, self.m1

    def guess(self, oracle: callable, ciphertext: bytes) -> int:
        # Ignora o criptograma e o oracle; responde ao acaso
        return random.randint(0, 1)




def IND_CPA(cipher: AbstractCipher, adversary: INDCPA_Adv) -> bool:


    # gerar a chave secreta (não é acessível ao adversário)
    key = cipher.keygen()

    # oracle de cifra que o adversário pode pedi-lo sempre que quiser
    # a chave está guardada via lambda e o adversário nunca a vê
    enc_oracle = lambda plaintext: cipher.enc(key, plaintext)

    # o adversário escolhe as suas duas mensagens candidatas
    m0, m1 = adversary.choose(enc_oracle)

    # o challenger escolhe um b pertencente a {0,1} de forma aleatória e cifra m[b]
    b = random.randint(0, 1)
    c = cipher.enc(key, m0 if b == 0 else m1)

    # o adversário tenta adivinhar qual das mensagens foi cifrada
    b_prime = adversary.guess(enc_oracle, c)

    # o adversário ganha se adivinhou corretamente
    return b_prime == b

def run_experiment(
    cipher: AbstractCipher,
    adversary: INDCPA_Adv,
    trials: int = 1000
) -> None:
    
    # corre o jogo 'trials' vezes e imprime as estatísticas.
    #    vantagem = 2 * |Pr[IND_CPA = True] - 1/2|

    
    # vantagem se for 0 entao o  adversário não melhor do que acaso (cifra segura)
     # se for 1, o  adversário ganha quase sempre 

  

    wins = sum(IND_CPA(cipher, adversary) for _ in range(trials))
    prob_win  = wins / trials
    advantage = 2 * abs(prob_win - 0.5)

    print(f"  advantage    : {advantage:.4f} ")





if __name__ == '__main__':

    print("Exemplo 1 —> cifra identidade")

    run_experiment(
        cipher    = IdentityCipher(),
        adversary = IdentityAdversary(),
        trials    = 1000
    )

   
    print("Exemplo 2 —> ChaCha20")

    run_experiment(
        cipher    = ChaCha20Cipher(),
        adversary = RandomAdversary(),
        trials    = 1000
    )

 