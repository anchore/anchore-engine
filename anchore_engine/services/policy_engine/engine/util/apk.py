"""
Utilities for working with APK packages in Alpine images

"""

def compare_versions(v1, op, v2):
    """
    Returns boolean True if op is true for v1 and v2
    :param v1:
    :param op:
    :param v2:
    :return: boolean true if op condition is met, false otherwise
    """
    if op == 'eq':
        return v1 == v2
    elif op == 'lt':
        return v1 < v2
    elif op == 'gt':
        return v1 > v2

    raise ValueError("invalid op specified in compare: " + str(op))