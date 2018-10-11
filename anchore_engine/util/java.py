"""
Java-related utilities for interacting with Java packages.
"""

import re
import anchore_engine.utils

def parse_properties(lines):
    """
    Parses the given line iterable using the Java properties file format.
    Lines beginning with # are ignored.
    :param lines: an iterable container of lines (bytes or strings)
    :return: the properties file as a dictionary
    """
    props = {}
    for line in lines:
        line = anchore_engine.utils.ensure_str(line)
        if not re.match(r"\s*(#.*)?$", line):
            kv = line.split('=')
            key = kv[0].strip()
            value = '='.join(kv[1:]).strip()
            props[key] = value
    return props