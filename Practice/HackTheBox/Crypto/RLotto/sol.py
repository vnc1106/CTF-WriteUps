from pwn import *
import time
import random

seed = int(time.time())

io = remote("206.189.122.191", 30277)

def sol(seed):
    random.seed(seed)
    extracted = []
    next_five = []

    while len(extracted) < 5:
        r = random.randint(1, 90)
        if(r not in extracted):
            extracted.append(r)

    solution = ""
    while len(next_five) < 5:
        r = random.randint(1, 90)
        if(r not in next_five):
            next_five.append(r)
            solution += str(r) + " "
    solution = solution.strip()
    return extracted, solution

for e in range(-3, 3, 1):
    print(sol(seed + e))

io.interactive()
# Flag: HTB{n3v3r_u53_pr3d1c74bl3_533d5_1n_p53ud0-r4nd0m_numb3r_63n3r470r}
