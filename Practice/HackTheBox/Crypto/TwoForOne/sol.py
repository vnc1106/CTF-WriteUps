from sage.all import *
from Crypto.Util.number import *
from Crypto.PublicKey import RSA
from pwn import *
from base64 import b64decode

key1 = RSA.importKey(open('./challenge/key1.pem', 'r').read())
key2 = RSA.importKey(open('./challenge/key2.pem', 'r').read())
c1 = b64decode(open('./challenge/message1', 'r').read())
c2 = b64decode(open('./challenge/message2', 'r').read())

n1, e1 = key1.n, key1.e
n2, e2 = key2.n, key2.e 

assert n1 == n2     # common modulus
_, u, v = xgcd(e1, e2)

m = pow(bytes_to_long(c1), u, n1) * pow(bytes_to_long(c2), v, n1) % n1
flag = long_to_bytes(ZZ(m))
info("Flag: " + flag.decode())

# Flag: HTB{C0mmon_M0dUlu5S_1S_b4D}
