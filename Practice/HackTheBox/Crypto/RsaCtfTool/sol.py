from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Util.number import *
from gmpy2 import iroot
from pwn import *

rsa_key = RSA.importKey(open('./challenge/pubkey.pem', 'r').read())
key = bytes.fromhex(open('./challenge/key', 'r').read())
enc = open('./challenge/flag.txt.aes', 'rb').read()[:-1]

N, e = rsa_key.n, rsa_key.e
p, check = iroot(N, 3)
assert check

d = inverse(e, p**2*(p - 1))
key = pow(bytes_to_long(key), d, N)

cipher = AES.new(long_to_bytes(key), AES.MODE_ECB)
flag = cipher.decrypt(enc)

info("Flag: " + flag.decode())
# Flag: HTB{pl4y1ng_w1th_pr1m3s_1s_fun!}
