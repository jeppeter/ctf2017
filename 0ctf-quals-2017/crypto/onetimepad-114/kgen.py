#! /usr/bin/env python

from os import urandom
import sys
import logging
import extargsparse

#P = 0x10000000000000000000000000000000000000000000000000000000000000425L
#P = 0x10425L
P=0x10322L


def process(m, k):
    tmp = m ^ k    
    logging.info('tmp [%x] bin[%s] P[%s]'%(tmp, bin(tmp)[2:], bin(P)[2:]))
    res = 0
    for i in bin(tmp)[2:]:
        res = res << 1;
        if (int(i)):
            res = res ^ tmp
            logging.info('res [%x] [%s]'%(res,bin(res)[2:]))
        if (res >> 16):
            res = res ^ P
        logging.info('res [%x] [%s]'%(res,bin(res)[2:]))
    return res

def keygen(seed,key):
    #key = str2num(urandom(2))
    while True:
        yield key
        key = process(key, seed)

def str2num(s):
    return int(s.encode('hex'), 16)


def parse_int(r):
    rint = 0
    base=10
    if r.startswith('x') or r.startswith('X'):
        base=16
        r = r[1:]
    elif r.startswith('0x') or r.startswith('0X'):
        base = 16
        r = r[2:]
    rint = int(r,base)
    return rint

def set_log_level(args):
    loglvl= logging.ERROR
    if args.verbose >= 3:
        loglvl = logging.DEBUG
    elif args.verbose >= 2:
        loglvl = logging.INFO
    elif args.verbose >= 1 :
        loglvl = logging.WARN
    # we delete old handlers ,and set new handler
    if logging.root is not None and logging.root.handlers is not None and len(logging.root.handlers) > 0:
        logging.root.handlers = []
    logging.basicConfig(level=loglvl,format='%(asctime)s:%(filename)s:%(funcName)s:%(lineno)d\t%(message)s')
    return

def genkey_handler(args,parser):
    global P
    set_log_level(args)
    P = args.parsenum
    seed = parse_int(args.subnargs[0])
    base = parse_int(args.subnargs[1])
    okey = base
    nkey = okey
    for i in range(args.times):
        nkey = process(okey,seed)
        print('[%d]P[0x%x]seed[0x%x] [0x%x]\n0x%x'%(i,P,seed,okey,nkey))
        okey = nkey
    sys.exit(0)
    return

def filter_handler(args,parser):
    global P
    set_log_level(args)
    P = args.parsenum
    seed = parse_int(args.subnargs[0])
    base = parse_int(args.subnargs[1])
    fnum = parse_int(args.subnargs[2])
    okey = base
    nkey = okey
    for i in range(args.times):
        nkey = process(okey,seed)
        if fnum == nkey:
            print('[%d]P[0x%x]seed[0x%x] [0x%x]\n0x%x'%(i,P,seed,okey,nkey))
        okey = nkey
    sys.exit(0)
    return


def main():
    global P
    commandline_fmt='''
    {
        "verbose|v" : "+",
        "parsenum|P" : %s,
        "random|R" : -1,
        "times|t" : 256,
        "genkey<genkey_handler>" : {
            "$" : 2
        },
        "filter<filter_handler>" : {
            "$" : 3
        }
    }
    '''
    commandline= commandline_fmt%(P)
    parser = extargsparse.ExtArgsParse()
    parser.load_command_line_string(commandline)
    parser.parse_command_line(None,parser)
    raise Exception('unknown subcommand [%s]'%(args.subcommand))
    return

if __name__ == '__main__':
    main()