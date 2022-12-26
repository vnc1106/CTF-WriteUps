from sage.all import *
from pwn import *
from Crypto.Util.number import *

def get_sign(num, guess):
    io.sendlineafter(b"Choice> ", b"1")
    io.sendlineafter(b"Enter the message you would like to sign, in hex> ", hex(num).encode()) 
    sig = io.recvline()[len("Signature: "): -1].decode()
    io.sendlineafter(b"Enter a guess for s, in hex> ", hex(guess).encode())   
    hints = [int(x) for x in io.recvline()[len("Hints: "):].split()]
    return int(sig, 16), hints

def get_pairs(n):
    pairs = []
    for m in range(n):
        io.sendlineafter(b"Choice> ", b"1")
        io.sendlineafter(b"Enter the message you would like to sign, in hex> ", hex(m).encode()) 
        sig = int(io.recvline()[len("Signature: "): -1].decode(), 16)
        guess = F(sig).nth_root(4, all=True)
        io.sendlineafter(b"Enter a guess for s, in hex> ", hex(guess[0]).encode())   
        guess.pop(0)

        c1, c2 = [int(x) for x in io.recvline()[len("Hints: "):].split()]
        guess.remove(c1)
        guess.remove(c2)
        pairs.append((m, guess[0]))
    return pairs

def get_flag(priv):
    io.sendlineafter("Choice> ", b"3")
    io.sendlineafter(b"Enter the private key as a list of space-separated numbers> ", b" ".join([str(x).encode() for x in priv]))

io = process(["python", "server.py"])
io.recvuntil(b"p = "); p = int(io.recvline())
F = GF(p)
pol = PolynomialRing(F, "x"); x = pol.gen()

points = get_pairs(100) # get 100 pairs
k = 25  # number of incorrect pairs ~ 25%
n = 32  # deg of polynomial we want to recover

# Ax = b
A = []
b = []

for (xi, yi) in points:
    b.append(F(-yi*xi**k))
    tmp = []
    for i in range(k): tmp.append(F(yi*xi**i))
    for i in range(n + k): tmp.append(F(-xi**i))
    A.append(tmp)

A = matrix(F, A)
b = vector(F, b)
sol = A.solve_right(b)

Ex = pol(list(sol[:k]) + [1])
Qx = pol(list(sol[k:]))

Fx = Qx/Ex 
priv = Fx.numerator().coefficients(sparse=False)

get_flag(priv)
io.interactive()

# Flag: corctf{wh0_n3eds_gue551ng_wh3n_y0u_have_l1ne4r_al6ebr4_526d95eadb9686bb}
# https://en.wikipedia.org/wiki/Berlekamp%E2%80%93Welch_algorithm