state_graphs = {
    'analyze': {
        'base_state': 'not_analyzed',
        'fault_state': 'analysis_failed',
        'queued_state': 'analysis_queued',
        'working_state': 'analyzing',
        'complete_state': 'analyzed',
        'transitions': {
            'init': 'not_analyzed',
            'not_analyzed':'analysis_queued',
            'analysis_queued':'analyzing',
            'analyzing':'analyzed',
            'analyzed':'analyzed'
        }
    },
    'policy_evaluate': {
        'base_state': 'not_evaluated',
        'fault_state': 'not_evaluated',
        'queued_state': 'evaluation_queued',
        'working_state': 'evaluating',
        'complete_state': 'evaluated',
        'transitions': {
            'init': 'not_evaluated',
            'not_evaluated':'evaluation_queued',
            'evaluation_queued':'evaluating',
            'evaluating':'evaluated',
            'evaluated':'evaluated'
        }
    },
    'image_status': {
        'base_state': 'active',
        'fault_state': 'inactive',
        'queued_state': 'active',
        'working_state': 'active',
        'complete_state': 'active',
        'transitions': {
            'init': 'active',
            'active':'active'
        }
    },
    'service_status': {
        'base_state': 'registered',
        'fault_state': 'unavailable',
        'queued_state': 'available',
        'working_state': 'available',
        'complete_state': 'available',
        'orphaned_state': 'orphaned',
        'transitions': {
            'init': 'registered',
            'registered':'available',
            'available':'available'
        }
    },
    'policy_engine_state': {
        'base_state': 'registered',
        'fault_state': 'unavailable',
        'queued_state': 'available',
        'working_state': 'syncing',
        'complete_state': 'available',
        'transitions': {
            'init': 'registered',
            'registered':'syncing',
            'syncing':'available'
        }
    }
}

def init_state(state_type, current_state, reset=False):
    if reset:
        return(reset_state(state_type))
    else:
        if current_state == None:
            return(base_state(state_type))
        else:
            return(current_state)

def reset_state(state_type):
    return(base_state(state_type))

def base_state(state_type):
    return(state_graphs[state_type]['base_state'])

def fault_state(state_type):
    return(state_graphs[state_type]['fault_state'])

def queued_state(state_type):
    return(state_graphs[state_type]['queued_state'])

def working_state(state_type):
    return(state_graphs[state_type]['working_state'])

def next_state(state_type, current_state):
    if not current_state:
        return(state_graphs[state_type]['transisitions']['init'])

    return(state_graphs[state_type]['transitions'][current_state])

def complete_state(state_type):
    return(state_graphs[state_type]['complete_state'])

def orphaned_state(state_type):
    if 'orphaned_state' in state_graphs[state_type]:
        ret = state_graphs[state_type]['orphaned_state']
    else:
        ret = state_graphs[state_type]['fault_state']
    return(ret)
