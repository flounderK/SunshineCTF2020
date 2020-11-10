#!/usr/bin/python3
from pwn import *
import monkeyhex
import re

# context.log_level = 'debug'
context.terminal = ['termite', '-e']

# lib = ELF('/usr/lib/libc.so.6') if not args.REMOTE else ELF('')
binary = context.binary = ELF('chall_09')

def attach_gdb(p, commands=None):
    """Template to run gdb with predefined commands on a process."""
    val = """
    """ if commands is None else commands
    return gdb.attach(p, val)


def new_proc(start_gdb=False, val=None):
    """Start a new process with predefined debug operations"""
    p = process(binary.path)
    if start_gdb is True:
        attach_gdb(p)
    return p

rexp = re.compile(b'0x[a-f0-9]+')
p = new_proc(False) if not args.REMOTE else remote('chal.2020.sunshinectf.org', int('30009'))

key = b'y\x17FU\x10S_]U\x10XUBU\x10D_:\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'

p.sendline(xor(key, 0x30))


p.interactive()
