#!/usr/bin/python3
from pwn import *
import monkeyhex

context.log_level = 'debug'
context.terminal = ['termite', '-e']

lib = ELF('/usr/lib/libc.so.6') if not args.REMOTE else ELF('')
binary = context.binary = ELF('oomg_space')

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

p = new_proc(True) if not args.REMOTE else remote('', int(''))
# do leak / payload gen here

p.sendafter(b'USER\n', b'admin')
p.sendafter(b'PASSWORD\n', b'A'*8)

payload = b''
# if args.DEBUG is True:
#     attach_gdb(p)
# p.sendline(payload)
# if args.DEBUG is True:
#     import ipdb as pdb; pdb.set_trace()

# p.interactive()
