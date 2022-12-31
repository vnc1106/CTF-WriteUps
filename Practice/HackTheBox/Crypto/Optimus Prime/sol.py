from pwn import *
from Crypto.Util.number import *

def get_data():
    io = remote("142.93.37.215", 31919)
    io.sendlineafter(b'Enter the option: ', b'4')
    io.recvuntil(b'PUBLIC KEY: '); N = int(io.recvline())
    io.recvuntil(b'ENCRYPTED PASSWORD: '); c = int(io.recvline())
    io.close()

    return N, c

def get_flag(p):
    io = remote("142.93.37.215", 31919)
    io.sendlineafter(b'Enter the option: ', b'4')
    io.recvuntil(b'PUBLIC KEY: '); N = int(io.recvline())
    io.recvuntil(b'ENCRYPTED PASSWORD: '); c = int(io.recvline())
    
    q = N//p 
    m = long_to_bytes(pow(c, inverse(e, (p - 1)*(q - 1)), N))
    io.sendlineafter(b'Please use it to proceed: ', m)
    io.interactive()

context.log_level = 'error'
n1, c1 = get_data()
n2, c2 = get_data()
e = 0x10001

p = GCD(n1, n2)
get_flag(p)

# Flag: HTB{3uc1id_w4z_th3_pr1me_h4x0r}
