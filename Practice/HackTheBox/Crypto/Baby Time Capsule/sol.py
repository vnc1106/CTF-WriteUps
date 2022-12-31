from Crypto.Util.number import long_to_bytes
from sage.all import *
from pwn import *
from json import *
from gmpy2 import *

def _recv(msg):
    return loads(msg.decode())

def get_data():
    io.sendlineafter(b'(Y/n) ', b'Y')
    data = _recv(io.recvline())
    ct, pubkey = data.values()
    return int(ct, 16), int(pubkey[0], 16)

io = remote("206.189.26.62", 31449)
N = []
C = []

info("Collecting data...")
for i in range(10):
    c, n = get_data()
    N.append(n)
    C.append(c) 

CT = crt(C, N)
m, check = iroot(int(CT), 5)
assert check
flag = long_to_bytes(m)

info("Flag: " + flag.decode())
# Flag: HTB{t3h_FuTUr3_15_bR1ghT_1_H0p3_y0uR3_W34r1nG_5h4d35!}
