from pwn import *

def xor(a, b):
    return bytes([x^y for x,y in zip(a, b)])

ct = bytes.fromhex("134af6e1297bc4a96f6a87fe046684e8047084ee046d84c5282dd7ef292dc9")

key = xor(ct[:4], b'HTB{')
flag = ''

for i in range(len(ct)):
    flag += chr(ct[i] ^ key[i % len(key)])

info('Flag: ' + flag)
# Flag: HTB{rep34t3d_x0r_n0t_s0_s3cur3}
