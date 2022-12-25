from pwn import *
from Crypto.Util.number import *

def send(num):
    io.sendlineafter(b"give me a number> ", str(num).encode())
    return int(io.recvline())

def dlp(a, g, p):
    for x in range(256):
        if pow(g, x, p) == a:
            return bytes([x])

io = process(["python", "server.py"])

g = int(io.recvline()[3:])
p = int(io.recvline()[3:])
io.recvuntil(b"encrypted flag: ")
ct = int(io.recvline())

flag = b""
for i in range(1, 65):
    c = send(256**(64 - i))
    flag += dlp(c * pow(g, -256*bytes_to_long(flag), p) % p, g, p)

print(flag)
# corctf{qu4drat1c_r3s1due_0r_n0t_1s_7h3_qu3st1on8852042051e57492}