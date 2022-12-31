from pwn import *

def xor(a, b):
    return bytes([x^y for x,y in zip(a, b)])

a = bytes.fromhex("6b65813f4fe991efe2042f79988a3b2f2559d358e55f2fa373e53b1965b5bb2b175cf039")
b = bytes.fromhex("fd034c32294bfa6ab44a28892e75c4f24d8e71b41cfb9a81a634b90e6238443a813a3d34")
c = bytes.fromhex("de328f76159108f7653a5883decb8dec06b0fd9bc8d0dd7dade1f04836b8a07da20bfe70")

flag = xor(a, xor(b, c))
info("Flag: " + flag.decode())
# Flag: HTB{s3cr3t_sh4r1ng_w1th_x0r_15_l4m3}
