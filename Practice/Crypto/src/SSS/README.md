# SSS (908 points)

> **Description**\
> `Math is so beautiful and can always be used for cryptographic encryption!`\
> `nc challenges1.hexionteam.com 5001`
>
> **Atachment**\
> **[SSS.py](./challenge/SSS.py)**

## Challenge overview

**`SSS.py:`**
```python
from Crypto.Util.number import bytes_to_long, getPrime
from random import randint
from secret import flag

MIN = randint(0x30, 0x40)
P = 2**521 - 1

def eval_at(poly, x, prime):
    """Evaluates polynomial (coefficient tuple) at x"""
    accum = 0
    for coeff in reversed(poly):
        accum *= x
        accum += coeff
        accum %= prime
    return accum

def main():
    poly = [bytes_to_long(flag.encode())]
    poly.extend(set([randint(1, P - 1) for i in range(MIN)]))
    print("┌───────────────┐")
    print("│ SSS Encryptor │")
    print("└───────────────┘")
    print("Enter text to encrypt, leave empty to quit.")
    while True:
        data = input(">>> ")
        if bytes_to_long(data.encode()) % P == 0:
            break
        print(eval_at(poly, bytes_to_long(data.encode()), P))  

if __name__ == "__main__":
    main()
```

We are given a prime number $P = 2^{521} - 1$ and a random polynomial $f(x) \in \mathbb{F}_{P}\[x\]$, where 

$$deg(f) < 0x40 \quad \text{and} \quad \text{flag} = f(0)$$

We can request any message $m$ (except $m = 0$) to the oracle and it will response a ciphertext $f(m)$

## Solution

Let:

$$f(x) = a_n \times x^{n} + a_{n-1} \times x^{n-1} + \cdots + a_{1} \times x + a_{0}, \qquad a_{i} \in \mathbb{F}_{P} \quad \forall i \in [0, n]$$

clearly that if we collect enough pairs $(x_{i}, f(x_{i}))$ (at least n + 1), we can easily recover $f(x)$ by solving this linear equation ($n + 1$ unknown variables - $n + 1$ equations):

$$
\begin{cases}
    a_n \times x_{1}^{n} + a_{n-1} \times x_{1}^{n-1} + \cdots + a_{1} \times x_{1} + a_{0} &= y_{1} \\\\
    a_n \times x_{2}^{n} + a_{n-1} \times x_{2}^{n-1} + \cdots + a_{1} \times x_{2} + a_{0} &= y_{2} \\\\
    &\vdots                                                                                            \\\\
    a_n \times x_{n + 1}^{n} + a_{n-1} \times x_{n + 1}^{n-1} + \cdots + a_{1} \times x_{n + 1} + a_{0} &= y_{n}
\end{cases} 
$$

or just simply use [Lagrange Interpolating Polynomial](https://en.wikipedia.org/wiki/Lagrange_polynomial) formula :stuck_out_tongue_winking_eye:

$$
\displaystyle f(x)=\sum_{j=0}^{n}y_{i}f_{j}(x).
$$

where

$$
\displaystyle 
\begin{aligned}
f_{j}(x) &= \frac{(x-x_{0})}{(x_{j}-x_{0})} \cdots \frac{(x-x_{j-1})}{(x_{j}-x_{j-1})} \frac{(x-x_{j+1})}{(x_{j}-x_{j+1})} \cdots \frac{(x-x_{n})}{(x_{j}-x_{n})} \\\\
\end{aligned}
$$

## Final script

```python
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
```

## Flag
**`hexCTF{d0nt_us3_shar3s_lik3_that}`**

