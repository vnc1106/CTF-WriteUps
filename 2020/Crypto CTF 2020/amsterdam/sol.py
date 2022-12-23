from sage.all import *
from Crypto.Util.number import *

enc = 5550332817876280162274999855997378479609235817133438293571677699650886802393479724923012712512679874728166741238894341948016359931375508700911359897203801700186950730629587624939700035031277025534500760060328480444149259318830785583493

def decrypt(c, k):
    m = 0
    c = ZZ(c).str(3)
    for char in c:
        m *= 2
        if char == '1':
            m += 1
        elif char == '2':
            m -= 1 
    m = [int(x) for x in bin(m)[2:]]
    n = len(m)

    msg = 0
    for i in range(2, n + 1):
        if m[i - 1] == 1:
            msg += binomial(n - i, k)
            k -= 1
    return long_to_bytes(msg)


for k in range(1000):
    flag = decrypt(enc, k)
    if b"CCTF{" in flag:
        print(flag)
        break

# CCTF{With_Re3p3ct_for_Sch4lkwijk_dec3nt_Encoding!}