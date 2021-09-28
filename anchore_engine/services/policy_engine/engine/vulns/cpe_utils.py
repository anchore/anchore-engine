import re
from typing import List

SIMPLIFIED_SEMVER_REGEX = r".*([0-9]+\.[0-9]+\.[0-9]+).*"


def generate_simple_cpes(name: str, version: str) -> List[str]:
    """
    Given a name and version, generate a list of fuzzy cpes and return it as a list
    of strings

    :param binary_name:
    :param binary_version:
    :return:
    """

    if not name:
        name = "*"
    if not version:
        version = "*"

    return [
        "cpe:2.3:a:-:{name}:{version}:*:*:*:*:*:*:*".format(name=name, version=version)
    ]


def generate_fuzzy_go_cpes(name: str, version: str) -> List[str]:
    """
    Generate a fuzzy list of cpes with some version processing if the version looks like a semver.

    :param name:
    :param version:
    :return:
    """

    candidate_versions = [version]

    patt = re.match(SIMPLIFIED_SEMVER_REGEX, version)
    if patt:
        simplified_version = patt.group(1)
        if simplified_version not in candidate_versions:
            candidate_versions.append(simplified_version)

    cpes = []
    for v in candidate_versions:
        cpes.extend(generate_simple_cpes(name, v))

    return cpes
