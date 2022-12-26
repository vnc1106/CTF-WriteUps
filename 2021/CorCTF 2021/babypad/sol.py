from pwn import *
from string import printable

def padding_oracle(ciphertext: bytes) -> bool:
    p.sendlineafter(b"> ", ciphertext.hex().encode())
    return int(p.recvline())

def xor(a, b):
    return bytes([x^y for x, y in zip(a, b)])

def attack_block(iv, block, orc, previous_block):
    m = b""
    letter = bytes(list(range(16, 0, -1))) + printable.encode()

    for pos in reversed(range(16)):
        padding = bytes(pos) + bytes([16 - pos]*(16 - pos))
        for c in letter:
            guess = bytes(pos) + bytes([c]) + m 
            payload = xor(block, xor(guess, padding))
            if orc(iv + previous_block + payload):
                m = bytes([c]) + m
                break
    return m

def attack(iv, c, orc):
    blocks = [c[i:i+16] for i in range(0, len(c), 16)]
    previous_block = b""
    flag = b""

    for block in blocks:
        flag += attack_block(iv, block, orc, previous_block)
        previous_block = block
    
    return flag
    
p  = process(["python", "chall.py"])
ct = bytes.fromhex(p.recvline()[:-1].decode())
iv, c = ct[:16], ct[16:]

print(attack(iv, c, padding_oracle))
# Flag: corctf{CTR_p4dd1ng?n0_n33d!}