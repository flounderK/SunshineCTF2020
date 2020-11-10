
import angr
import claripy
import monkeyhex


project_kwargs = dict()
project_kwargs['auto_load_libs'] =  False
project_kwargs['use_sim_procedures'] = True
project = angr.Project('oomg_space', **project_kwargs)


def ascii_only_constraint(variable, state):
	for b in variable.chop(8):
		state.add_constraints(claripy.And(b >= 0x20, b < 0x7f))
kwargs = {}

simgr_kwargs = {}

buf_len = 8
stdin_bvs = claripy.BVS('stdin_bvs', buf_len*8)
kwargs['stdin'] = stdin_bvs
kwargs['addr'] = 0x04014ad
initial_state = project.factory.blank_state(**kwargs)

ascii_only_constraint(stdin_bvs, initial_state)

padding_length_b = 8
initial_state.regs.rsp -= padding_length_b


def is_successful(state):
	stdout_output = state.posix.dumps(1)
	return stdout_output.find(b'LOGIN SUCCESS') > -1

def should_abort(state):
	stdout_output = state.posix.dumps(1)
	return stdout_output.find(b'LOGIN FAIL') > -1


simgr = project.factory.simgr(initial_state, **simgr_kwargs)
simgr.explore(find=is_successful, avoid=should_abort)
