from sage.all import *
from Crypto.Util.number import bytes_to_long, long_to_bytes
from pwn import *

def encrypt(m: bytes):
    io.sendlineafter(b'>>> ', m)
    return (bytes_to_long(m), int(io.recvline()))


io = process(["python", "./challenge/SSS.py"])

P = 2**521 - 1
deg = 0x40
points = [encrypt(b'a'*i) for i in range(1, deg + 2)]

R = PolynomialRing(GF(P), "x"); x = R.gen()
m = R.lagrange_polynomial(points)[0]

info("Flag: " + long_to_bytes(ZZ(m)).decode())
