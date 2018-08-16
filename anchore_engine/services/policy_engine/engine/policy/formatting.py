import datetime
import uuid

policy_line_format='{gate}:{trigger}:{action}'
param_format='{name}={value} '
whitelist_format='{gate} {trigger}'

def policy_json_to_txt(policy_json):
    """
    Taken from nurmi's branch of anchore.

    :param policy_json: a parsed json object that is a single policy from the Anchore PolicyBundle format
    :return native anchore policy document as a string to be written to a file
    """
    ret = []
    if policy_json and policy_json.get('version', None) == '1_0':
        for item in policy_json['rules']:
            line = policy_line_format.format(gate=item['gate'], trigger=item['trigger'], action=item['action'])
            if 'params' in item:
                line += ':'
                for param in item['params']:
                    line += param_format.format(name=param['name'], value=param['value'])
            ret.append(line)

    return ret


def whitelist_json_to_txt(whitelist_json):
    """
    Taken from nurmi's branch of anchore
    """

    ret = []
    if whitelist_json.get('version',None) == '1_0':
        for item in whitelist_json['items']:
            ret.append(whitelist_format.format(gate=item['gate'], trigger=item['trigger_id']))

    return ret


def policy_txt_to_json(policy_txt):
    """
    Convert a newline delimited string (e.g. read from a file) to a policy json in v1_0 format
    :param policy_txt: single string of all lines with \n intact
    :return: json object of 1_0 version policy object
    """
    gen_date = datetime.datetime.utcnow().isoformat()
    policy = {
        'id': uuid.uuid4().get_hex(), # Generate an id
        'name': 'GeneratedPolicy-{}'.format(gen_date),
        'version': '1_0',
        'comment': 'Policy json generated automatically from raw txt document on {}'.format(gen_date),
        'rules': []
    }
    for line in policy_txt.splitlines():
        if line.startswith('#') or len(line.strip()) == 0:
            continue

        tokens = line.split(':')
        if len(tokens) > 3:
            params = ':'.join(tokens[3:]).split(' ')
        else:
            params = []

        policy['rules'].append({
            'gate': tokens[0],
            'trigger': tokens[1],
            'action': tokens[2],
            'params': [{'name': x[0], 'value': x[1]} for x in [y.split('=') for y in params]]
        })
    return policy

def whitelist_txt_to_json(whitelist_txt):
    gen_date = datetime.datetime.utcnow().isoformat()
    whitelist = {
        'id': uuid.uuid4().get_hex(),  # Generate an id
        'name': 'GeneratedWhitelist-{}'.format(gen_date),
        'version': '1_0',
        'comment': 'Whitelist json generated automatically from raw txt document on {}'.format(gen_date),
        'items': []
    }
    for line in whitelist_txt.splitlines():
        if line.startswith('#') or len(line.strip()) == 0:
            continue

        tokens = line.split(' ')

        whitelist['items'].append({
            'gate': tokens[0],
            'trigger_id': tokens[1]
        })
    return whitelist

conversion_map = {
    'whitelist': {
        str: whitelist_txt_to_json,
        dict: whitelist_json_to_txt
    },
    'policy': {
        str: policy_txt_to_json,
        dict: policy_json_to_txt
    }
}