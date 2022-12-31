from pwn import *

def xor(a, b):
    return bytes([x^y for x,y in zip(a, b)])

io = remote("139.59.171.86", 31201)
io.sendlineafter(b'username: ', b'Admin')
io.sendlineafter(b"Admin\'s password: ", b'g0ld3n_b0y')

io.recvuntil(b'Leaked ciphertext: ')
enc = bytes.fromhex(io.recvline()[:-1].decode())

iv = xor(enc[:16], xor(b'a', b'A') + bytes(15))

payload = iv + enc[16:]
io.sendlineafter(b'enter ciphertext: ', payload.hex().encode())

io.interactive()
# Flag: HTB{b1t_fl1pp1ng_1s_c00l}
