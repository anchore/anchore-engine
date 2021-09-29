"""
Module for centralizing cpe generation code. Most of this will be removed as syft takes over all the cpe generation
duty, so this module is not expected to grow.
"""
# Note: this duplicates a lot of code from the policy engine loader, that code will be removed in the future so refactoring
# it to use these functions has limited value.

import re
from typing import List
from anchore_engine.subsys import logger

SIMPLIFIED_SEMVER_REGEX = r".*([0-9]+\.[0-9]+\.[0-9]+).*"
VENDORLESS_CPE_FORMAT = "cpe:2.3:a:-:{name}:{version}:*:*:*:*:*:*:*"
VERSION_CLEANUP_REGEX = r"\.(RELEASE|GA|SEC.*)$"

# this is a static mapping of known package names (keys) to official cpe names for each package
NOMATCH_INCLUSIONS = {
    "java": {
        "springframework": ["spring_framework", "springsource_spring_framework"],
        "spring-core": ["spring_framework", "springsource_spring_framework"],
    },
    "npm": {
        "hapi": ["hapi_server_framework"],
        "handlebars.js": ["handlebars"],
        "is-my-json-valid": ["is_my_json_valid"],
        "mustache": ["mustache.js"],
    },
    "gem": {
        "Arabic-Prawn": ["arabic_prawn"],
        "bio-basespace-sdk": ["basespace_ruby_sdk"],
        "cremefraiche": ["creme_fraiche"],
        "html-sanitizer": ["html_sanitizer"],
        "sentry-raven": ["raven-ruby"],
        "RedCloth": ["redcloth_library"],
        "VladTheEnterprising": ["vladtheenterprising"],
        "yajl-ruby": ["yajl-ruby_gem"],
    },
    "python": {
        "python-rrdtool": ["rrdtool"],
    },
}


def generate_simple_cpes(name: str, version: str) -> List[str]:
    """
    Given a name and version, generate a list of fuzzy cpes and return it as a list
    of strings

    :param name: package name
    :param version: package version
    :return: list of CPE 2.3 strings for the given package name and version
    """

    if not name:
        name = "*"
    if not version:
        version = "*"

    return [VENDORLESS_CPE_FORMAT.format(name=name, version=version)]


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


def generate_products(name: str, package_type: str) -> List[str]:
    """
    Generates alternative product names from the input name and package type using the NOMATCH_INCLUSION map

    :param name:
    :param package_type:
    :return:
    """
    ret_names = [name]

    for n in NOMATCH_INCLUSIONS.get(package_type, {}).get(name, []):
        if n not in ret_names:
            ret_names.append(n)

    return ret_names


def generate_python_products(name: str) -> List[str]:
    return generate_products(name, "python")


def generate_npm_products(name: str) -> List[str]:
    return generate_products(name, "npm")


def generate_gem_products(name: str) -> List[str]:
    return generate_products(name, "gem")


def cleaned_version(version: str) -> str:
    """
    Clean a version string to remove release parts, etc
    :param version:
    :return:
    """
    return re.sub(VERSION_CLEANUP_REGEX, "", version)


def generate_java_cpes(image_content_dict: dict) -> List[str]:
    """
    Convert a entry from the image content dict into a list of CPE strings

    :param image_content_dict:
    :return:
    """

    known_nomatch_inclusions = NOMATCH_INCLUSIONS.get("java", {})

    ret_names = []
    ret_versions = [
        image_content_dict.get("implementation-version", "N/A"),
        image_content_dict.get("specification-version", "N/A"),
        image_content_dict.get("maven-version", "N/A"),
    ]

    for rversion in ret_versions:
        clean_version = cleaned_version(rversion)
        if clean_version not in ret_versions:
            ret_versions.append(clean_version)

    try:
        t_names, t_versions = tokenize(image_content_dict=image_content_dict)
        ret_names.extend(t_names)
        ret_versions.extend(t_versions)
    except Exception as err:
        logger.warn(
            "Error tokenizing java metadata for cpe generation. Continuing. Err = %s",
            err,
        )

    for rname in list(ret_names):
        underscore_name = hyphen_to_underscore(rname)
        if underscore_name not in ret_names:
            ret_names.append(underscore_name)

    for rname in list(ret_names):
        for product in generate_products(rname, "java"):
            if product not in ret_names:
                ret_names.append(product)

    cpes = []
    for name in ret_names:
        for version in ret_versions:
            cpes.extend(generate_simple_cpes(name, version))

    deduped_cpes = list(set(cpes))
    return deduped_cpes


def tokenize(image_content_dict: dict) -> tuple:

    names = []
    versions = []

    # do some heuristic tokenizing

    toks = re.findall("[^-]+", image_content_dict["package"])
    firstname = None
    fullname = []
    firstversion = None
    fullversion = []

    doingname = True
    for tok in toks:
        if re.match("^[0-9]", tok):
            doingname = False

        if doingname:
            if not firstname:
                firstname = tok
            else:
                fullname.append(tok)
        else:
            if not firstversion:
                firstversion = tok
            else:
                fullversion.append(tok)

    if firstname:
        firstname_nonums = re.sub("[0-9].*$", "", firstname)
        for gthing in [firstname, firstname_nonums]:
            if gthing not in names:
                names.append(gthing)
            if "-".join([gthing] + fullname) not in names:
                names.append("-".join([gthing] + fullname))

    if firstversion:
        firstversion_nosuffix = cleaned_version(firstversion)
        for gthing in [firstversion, firstversion_nosuffix]:
            if gthing not in versions:
                versions.append(gthing)
            if "-".join([gthing] + fullversion) not in versions:
                versions.append("-".join([gthing] + fullversion))

    # attempt to get some hints from the manifest, if available
    manifest = image_content_dict["metadata"].get("MANIFEST.MF", None)
    if manifest:
        pnames = []
        manifest = re.sub("\r\n ", "", manifest)
        for mline in manifest.splitlines():
            if mline:
                key, val = mline.split(" ", 1)
                if key.lower() == "export-package:":
                    val = re.sub(';uses:=".*?"', "", val)
                    val = re.sub(';version=".*?"', "", val)
                    val = val.split(";")[0]
                    pnames = pnames + val.split(",")

        packagename = None
        if pnames:
            shortest = min(pnames)
            longest = max(pnames)
            if shortest == longest:
                packagename = shortest
            else:
                for i in range(0, len(shortest)):
                    if i > 0 and shortest[i] != longest[i]:
                        packagename = shortest[: i - 1]
                        break
        if packagename:
            candidate = packagename.split(".")[-1]
            known_nomatch_inclusions = NOMATCH_INCLUSIONS.get("java")

            if candidate in list(known_nomatch_inclusions.keys()):
                for matchmap_candidate in known_nomatch_inclusions[candidate]:
                    if matchmap_candidate not in names:
                        names.append(matchmap_candidate)
            elif candidate not in ["com", "org", "net"] and len(candidate) > 2:
                for r in list(names):
                    if r in candidate and candidate not in names:
                        names.append(candidate)

    return names, versions


def hyphen_to_underscore(name: str) -> str:
    """
    Convert a name with hyphens into underscores.

    If none are found, the same string is returned

    :param name:
    :return:
    """
    return re.sub("-", "_", name)
