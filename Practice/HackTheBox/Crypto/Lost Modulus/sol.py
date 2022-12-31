from pwn import *
from Crypto.Util.number import *
from gmpy2 import iroot

enc = bytes.fromhex("05c61636499a82088bf4388203a93e67bf046f8c49f62857681ec9aaaa40b4772933e0abc83e938c84ff8e67e5ad85bd6eca167585b0cc03eb1333b1b1462d9d7c25f44e53bcb568f0f05219c0147f7dc3cbad45dec2f34f03bcadcbba866dd0c566035c8122d68255ada7d18954ad604965")
m, check = iroot(bytes_to_long(enc), 3)
assert check

info("Flag: " + long_to_bytes(m).decode())
# Flag: HTB{n3v3r_us3_sm4ll_3xp0n3n7s_f0r_rs4}
