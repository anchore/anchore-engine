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
            idx = line.find('=')
            if idx > -1:
                key = line[0:idx].strip()
                value = line[idx+1:].strip()
                props[key] = value
    return props

def parse_manifest(lines):
    """
    Parses the given line iterable using the JAR manifest file format.
    Note that this only parses the main section and attributes.
    :param lines: an iterable container of lines
    :return: the main attributes of the manifest file as a dictionary
    """
    full_lines = []
    for line in lines:
        line = anchore_engine.utils.ensure_str(line)
        if line.startswith(' '):
            full_lines[-1] += line[1:]
        else:
            full_lines.append(line)
    attrs = {}
    for line in full_lines:
        idx = line.find(':')
        if idx > -1:
            key = line[0:idx]
            value = line[idx+1:].lstrip()
            attrs[key] = value
    return attrs
