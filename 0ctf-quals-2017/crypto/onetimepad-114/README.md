# onetimepad-114的解法思路

> 这里使用的参考是 [http://mslc.ctf.su/wp/0ctf-2017-quals-onetimepad-1-and-2/](http://mslc.ctf.su/wp/0ctf-2017-quals-onetimepad-1-and-2/)

```python
from os import urandom
 
def process(m, k):
    tmp = m ^ k
    res = 0
    for i in bin(tmp)[2:]:
        res = res << 1;
        if (int(i)):
            res = res ^ tmp
        if (res >> 256):
            res = res ^ P
    return res
 
def keygen(seed):
    key = str2num(urandom(32))
    while True:
        yield key
        key = process(key, seed)
 
def str2num(s):
    return int(s.encode('hex'), 16)
 
P = 0x10000000000000000000000000000000000000000000000000000000000000425L


fake_secret1 = "I_am_not_a_secret_so_you_know_me"
fake_secret2 = "feeddeadbeefcafefeeddeadbeefcafe"

c1 = 0xaf3fcc28377e7e983355096fd4f635856df82bbab61d2c50892d9ee5d913a07f
c2 = 0x630eb4dce274d29a16f86940f2f35253477665949170ed9e8c9e828794b5543c
c3 = 0xe913db07cbe4f433c7cdeaac549757d23651ebdccf69d7fbdfd5dc2829334d1b
 
k2 = c2 ^ str2num(fake_secret1)
k3 = c3 ^ str2num(fake_secret2)
 
kt = k3
for i in xrange(255):
    kt = process(kt, 0)
 
seed = kt ^ k2
print "SEED", seed
assert process(k2, seed) == k3
 
kt = k2
for i in xrange(255):
    kt = process(kt, 0)
 
k1 = kt ^ seed
print "K1", seed
assert process(k1, seed) == k2
 
m = k1 ^ c1
print `hex(m)[2:-1].decode("hex")`

```

> 这里的最大思路是原来的的算法是 (m + k)^2 ，这里的+不是普通的加法，是在二项式中所用的xor的加法，具体请参考一般加密解密中关于二项式域中的加密算法，或者是《密码编码学与网络安全-原理与实践第5版》中的内容，这样，我们的解法就是把这个得到的数据进行255次的处理，这样就可以得到原来的SEED了，上面的算法就是这样实现的。