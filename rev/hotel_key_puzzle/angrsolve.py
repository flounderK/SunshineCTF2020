
import angr
import claripy
import monkeyhex


project_kwargs = dict()
project_kwargs['auto_load_libs'] =  False
project_kwargs['use_sim_procedures'] = True
project = angr.Project('hotel_key_puzzle', **project_kwargs)



kwargs = {}

simgr_kwargs = {}



initial_state = project.factory.entry_state(**kwargs)


def is_successful(state):
	stdout_output = state.posix.dumps(1)
	return stdout_output.find(b"I see you found the key, hopefully your bags are in your room by this point.") > -1

def should_abort(state):
	stdout_output = state.posix.dumps(1)
	return stdout_output.find(b'Sadly,') > -1


simgr = project.factory.simgr(initial_state, **simgr_kwargs)
simgr.explore(find=is_successful, avoid=should_abort)
print(simgr.one_found.posix.dumps(0))
