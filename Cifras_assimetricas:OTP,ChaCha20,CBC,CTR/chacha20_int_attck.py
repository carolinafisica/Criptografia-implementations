import sys

def attack(fctxt, pos, ptxt_at_pos, new_ptxt_at_pos):
    with open(fctxt, 'rb') as f:
        data = bytearray(f.read())

    nonce_len = 16
    p = ptxt_at_pos.encode()
    n = new_ptxt_at_pos.encode()

    # os primeiros 16 bytes são o nonce, o criptograma começa em data[16:]
    for i in range(len(p)):
        data[nonce_len + pos + i] ^= p[i] ^ n[i]

    out_file = fctxt + '.attck'
    with open(out_file, 'wb') as f:
        f.write(data)

if __name__ == '__main__':
 
    attack(sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4])

# o ataque é por exemplo, na frase "Ola, o meu nome e Carolina", sei que na posição 17 está Carolina e quero mudar para Alex
# Cifrar:   C[i] = P[i]  XOR  K[i]; P é a mensagem
# Decifrar: P[i] = C[i]  XOR  K[i]
# Se eu sei que P[i] = 'C' e quero que passe a ser 'A', basta fazer C_novo[i] = C[i]  XOR  'C'  XOR  'A'
# E ao ser decifrado, 
# C_novo[i] XOR K[i]  =  C[i] XOR 'C' XOR 'A' XOR K[i]
                 #=  P[i] XOR 'C' XOR 'A'
                 #=  'C'  XOR 'C' XOR 'A'
                 #=  'A'   

