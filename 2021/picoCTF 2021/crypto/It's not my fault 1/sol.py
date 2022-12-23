from pwn import *
from hashlib import md5
from Crypto.Util.number import *

io = remote("mercury.picoctf.net", 26695)
data = io.recvline()
_hash = data[-7:-1].decode()
_prefix = data.split(b"\"")[1].decode()
info("==POW==")
info("preffix: " + _prefix)
info("suffix md5: " + _hash)

_suffix = 0
while True:
    tmp = _prefix + str(_suffix)
    if md5(tmp.encode()).hexdigest().endswith(_hash):
        info("Found: " + tmp)
        io.sendline(tmp.encode())
        break
    _suffix += 1

io.recvuntil(b"Public Modulus :  "); N = int(io.recvline())
io.recvuntil(b"Clue :  "); e = int(io.recvline())

info("N = " + str(N))
info("e = " + str(e))

for dp in range(1, 1 << 20):

    p = GCD(pow(2, e*dp, N) - 2, N)
    if isPrime(p):
        q = N // p 
        info("p = " + str(p))
        info("q = " + str(q))
        io.sendline(str(p + q).encode())
        io.interactive()
        exit()
