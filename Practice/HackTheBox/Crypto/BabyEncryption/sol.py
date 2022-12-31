from pwn import *

def decrypt(ct):
    msg = []
    for c in ct:
        msg.append((c - 18) * pow(123, -1, 256) % 256)
    return bytes(msg)

ct = bytes.fromhex(open('./challenge/msg.enc', 'r').read())
flag = decrypt(ct)

info(flag.decode())
# Flag: HTB{l00k_47_y0u_r3v3rs1ng_3qu4710n5_c0ngr475}
