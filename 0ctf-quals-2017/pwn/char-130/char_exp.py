#! /usr/bin/env python

from os import urandom
import sys
import logging
import extargsparse


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


def format_c(startc,endc):
	rets = ''
	for i in range(startc,endc,1):
		rets += chr(i)
	return rets

def genkey_handler(args,parser):
	set_log_level(args)
	s = format_c(parse_int(args.subnargs[0]),parse_int(args.subnargs[1]))
	sys.stdout.write('%s\n'%(s))
	sys.exit(0)
	return

def main():
    commandline='''
    {
        "verbose|v" : "+",
        "genkey<genkey_handler>" : {
            "$" : 2
        }
    }
    '''
    parser = extargsparse.ExtArgsParse()
    parser.load_command_line_string(commandline)
    parser.parse_command_line(None,parser)
    raise Exception('unknown subcommand [%s]'%(args.subcommand))
    return

if __name__ == '__main__':
    main()