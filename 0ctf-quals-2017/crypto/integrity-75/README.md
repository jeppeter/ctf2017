# integerity 分析报告 [原文地址](https://devcraft.io/posts/2017/03/20/integrity-0ctf.html)
> [integrity_f2ed28d6534491b42c922e7d21f59495.zip](./integrity_f2ed28d6534491b42c922e7d21f59495.zip)

> 这里使用是把原文进行了理解的文章，
> 这里其实想找的是怎么可以得到admin的secret， 这个本身是不可能得到直接的内容，但可以得到相应的内容了，说白了，
> 
```python
#!/usr/bin/env python

from pwn import *
from hashlib import md5

BS = 16
pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS) 
unpad = lambda s : s[0:-ord(s[-1])]


name = md5(pad("admin")).digest() + "admin"

r = remote("202.120.7.217", 8221)

r.sendlineafter("or [l]ogin\n", "r")
r.sendline(name)
r.recvuntil("secret:\n")
secret = r.recvline().strip()

r.sendlineafter("or [l]ogin\n", "l")
r.sendline(secret[32:])
r.interactive()

"""
Welcome admin!
flag{Easy_br0ken_scheme_cann0t_keep_y0ur_integrity}
"""
```
上面的代码，先把admin形成一个数据，因为加密，其实得到了前面的32个字节就是我们想要得到的数据，再一解吗，就是我们得到的数据，如下面的形式
username ("md5admin+admin") ==>          pad ("md5admin+admin          ")  ==> (iv + enc(md5admin)+enc(admin)) 
解码的时候
encusername(enc(md5admin) + enc(admin)) ==> md5admin + admin
这里面最大的原因是因为CBC有一个特性，就是它的IV第一个我们输入的，但后面的是依据前面的一个块的加密内容成为IV，这个特性很重要，是这里面的关键

