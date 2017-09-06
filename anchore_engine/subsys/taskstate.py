state_graphs = {
    'analyze': {
        'base_state': 'not_analyzed',
        'fault_state': 'analysis_failed',
        'working_state': 'analyzing',
        'complete_state': 'analyzed',
        'transitions': {
            'init': 'not_analyzed',
            'not_analyzed':'analyzing',
            'analyzing':'analyzed',
            'analyzed':'analyzed'
        }
    },
    'policy_evaluate': {
        'base_state': 'not_evaluated',
        'fault_state': 'not_evaluated',
        'working_state': 'evaluating',
        'complete_state': 'evaluated',
        'transitions': {
            'init': 'not_evaluated',
            'not_evaluated':'evaluating',
            'evaluating':'evaluated',
            'evaluated':'evaluated'
        }
    },
    'image_status': {
        'base_state': 'active',
        'fault_state': 'inactive',
        'working_state': 'active',
        'complete_state': 'active',
        'transitions': {
            'init': 'active',
            'active':'active'
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

def working_state(state_type):
    return(state_graphs[state_type]['working_state'])

def next_state(state_type, current_state):
    if not current_state:
        return(state_graphs[state_type]['transisitions']['init'])

    return(state_graphs[state_type]['transitions'][current_state])

def complete_state(state_type):
    return(state_graphs[state_type]['complete_state'])

