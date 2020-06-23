import pytest
from anchore_engine.plugins.authorization.client import Action, AuthorizationDecision, AuthorizationRequest, Domain, Principal


def should_marshal(obj, target_type):
    return target_type.from_json(obj)


def should_not_marshal(obj, target_type):
    with pytest.raises(ValueError):
        target_type.from_json(obj)
    return True


def positive_check(candidates, target_type):
    return [x for x in map(lambda x: should_marshal(x, target_type), candidates)]


def negative_check(candidates, target_type):
    return [x for x in map(lambda x: should_not_marshal(x, target_type), candidates)]


def test_domain_model_positive():
    positive_check([
        {'name': 'somedomain'},
        {'name': ''}],
        Domain)
    return True


def test_domain_model_negative():
    negative_check([
        {'name': 'somedomain', 'badkey': 'badvalue'},
        {'n': ''},
        {}],
        Domain)
    return True


def test_principal_model_positive():
    positive_check([
        {'name': 'somedomain'},
        {'name': ''}],
        Principal)
    return True


def test_principal_model_negative():
    negative_check([
        {'name': 'somedomain', 'badkey': 'badvalue'},
        {'n': ''},
        {}],
        Principal)
    return True


def test_action_model_positive():
    positive_check(
        [
            {'domain': 'somedomain', 'action': 'act1', 'target': 't1'}
        ],
        Action)
    return True


def test_action_model_negative():
    negative_check(
        [
            {},
            {'domain': ''},
            {'blah': '', 'domain': 'blah2'}
        ],
        Action)
    return True


def test_authorizationrequest_model_positive():
    positive_check([
        {
            'principal': {'name': 'user'},
            'actions': [
                {'domain': 'd', 'action': 'a', 'target': 't'},
                {'domain': 'd1', 'action': 'a2', 'target': 't2'}
            ]
        },
        {'principal': {'name': 'user'},
         'actions': [{'domain': 'd', 'action': 'a', 'target': 't'}, {'domain': 'd1', 'action': 'a2', 'target': 't2'}]},
        {'principal': {'name': 'user'},
         'actions': [{'domain': 'd', 'action': 'a', 'target': 't'}, {'domain': 'd1', 'action': 'a2', 'target': 't2'}]}
        ],
        AuthorizationRequest)
    return True


def test_authorizationrequest_model_negative():
    negative_check([
        {'principals': {'name': 'user'},
         'actions': [{'domain': 'd', 'action': 'a', 'target': 't'}, {'domain': 'd1', 'action': 'a2', 'target': 't2'}]},
        {'principal': {'name': 'user'},
         'actions': {'domain': 'd', 'action': 'a', 'target': 't'}},
        {'principal': {'name': 'user'},
         'actions': [{'domain': 'd', 'action': 'a', 'target': 't'}, {'domain': 'd1', 'action': 'a2', 'target': 't2'}],
         'extras': 'blah'},
        {}],
        AuthorizationRequest)
    return True


def test_authorizationdecision_model_positive():
    positive_check([
        {
            'principal': {'name': 'user'},
            'allowed': [
                {'domain': 'd', 'action': 'a', 'target': 't'},
                {'domain': 'd1', 'action': 'a2', 'target': 't2'}
            ],
            'denied': [
                {'domain': 'd', 'action': 'a', 'target': 't'},
                {'domain': 'd1', 'action': 'a2', 'target': 't2'}
            ],
            'ttl': 10
        },
        {
            'principal': {'name': 'user'},
            'allowed': [],
            'denied': [
                {'domain': 'd', 'action': 'a', 'target': 't'},
                {'domain': 'd1', 'action': 'a2', 'target': 't2'}
            ],
            'ttl': 10
        },
        {
            'principal': {'name': 'user'},
            'allowed': [
                {'domain': 'd', 'action': 'a', 'target': 't'},
                {'domain': 'd1', 'action': 'a2', 'target': 't2'}
            ],
            'denied': [],
            'ttl': 10
        },
        {
            'principal': {'name': 'user'},
            'allowed': [],
            'denied': [],
            'ttl': 10
        }
        ],
        AuthorizationDecision)
    return True


def test_authorizationdecision_model_negative():
    negative_check([
        {
            'principal': {},
            'allowed': [
                {'domain': 'd', 'action': 'a', 'target': 't'}
            ],
            'denied': [
                {'domain': 'd', 'action': 'a', 'target': 't'}
            ],
            'ttl': 10
        },
        {
            'principal': {'name': 'user'},
            'denied': [
                {'domain': 'd', 'action': 'a', 'target': 't'}
            ],
            'ttl': 10
        },
        {
            'principal': {'name': 'user'},
            'allowed': [
                {'domain': 'd', 'action': 'a', 'target': 't'},
                {'domain': 'd1', 'action': 'a2', 'target': 't2'}
            ],
            'denied': [],
            'ttl': 10,
            'extra': 123
        },
        {
            'principal': {'name': 'user'},
            'allowed': [
                {'domain': 'd', 'action': 'a', 'target': 't'},
                {'domainz': 'd1', 'action': 'a2', 'target': 't2'}
            ],
            'denied': [],
            'ttl': 10,
            'extra': 123
        },
        {
            'principal': {'name': 'user'},
            'allowed': [],
            'denied': []
        }
    ],
        AuthorizationDecision)
    return True
