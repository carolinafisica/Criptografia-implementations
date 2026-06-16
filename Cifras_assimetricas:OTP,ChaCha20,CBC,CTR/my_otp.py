import os
import sys
import random

def seed_expand(x):
    r = x
    for _ in range(14):
        y = x >> 8
        x ^= y
        r ^= x
        x = y
    return r

def my_prng(n):
    """ a ?SECURE? pseudo-random number generator """
    myseed = os.urandom(16)
    random.seed(seed_expand(int.from_bytes(myseed, byteorder='little')))
    return random.randbytes(n)




def xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))




def setup(n, keyfile):
    key = my_prng(n)
    with open(keyfile,"wb") as f: # write binary
        f.write(key)



def enc(msgfile, keyfile):
    with open(msgfile,"rb") as f: # read binary
        msg = f.read()
    with open(keyfile,"rb") as f:
        key = f.read()

    cp = xor(msg, key)
    with open(msgfile + ".enc", "wb") as f:
        f.write(cp)



def dec(cpfile, keyfile):
    with open(cpfile, "rb") as f:
        cp = f.read()
    with open(keyfile, "rb") as f:
        key = f.read()

    deci = xor(cp, key)
    with open(cpfile + ".dec", "wb") as f:
        f.write(deci)



if __name__ == "__main__":

    cmd = sys.argv[1]

    if cmd == "setup":
        setup(int(sys.argv[2]), sys.argv[3])
    elif cmd == "enc":
        enc(sys.argv[2], sys.argv[3])
    elif cmd == "dec":
        dec(sys.argv[2], sys.argv[3])