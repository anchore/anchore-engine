#!/usr/bin/env python3

import os
import collections

from anchore_engine.analyzers.utils import dig, defaultdict_to_dict
from anchore_engine.clients.syft_wrapper import run_syft


def handle_java(findings, artifact):
    """Java results handler for syft output.

    Args:
        findings (dict): nested dictionary representing a json structure.
        artifact (json): datastructure presented by syft.

    Returns:
        dict: findings dictionary is populated with values from the provided
              artifact.
    """
    
    pkg_key = dig(artifact, 'metadata', 'virtualPath', default="N/A")

    virtualElements = pkg_key.split(":")
    if "." in virtualElements[-1]:
        # there may be an extension in the virtual path, use it
        java_ext = virtualElements[-1].split(".")[-1]
    else:
        # the last field is probably a package name, use the second to last virtual path element and extract the extension
        java_ext = virtualElements[-2].split(".")[-1]

    # per the manifest specification https://docs.oracle.com/en/java/javase/11/docs/specs/jar/jar.html#jar-manifest
    # these fields SHOULD be in the main section, however, there are multiple java packages found
    # where this information is thrown into named subsections.
    
    # Today anchore-engine reads key-value pairs in all sections into one large map --this behavior is replicated here.

    values = {}

    main_section = dig(artifact, 'metadata', 'manifest', 'main', default={})
    named_sections = dig(artifact, 'metadata', 'manifest', 'namedSections', default={})
    for name, section in [('main', main_section)] + [pair for pair in named_sections.items()]:
        for field, value in section.items():
            values[field] = value

    # find the origin
    group_id = dig(artifact, 'metadata', 'pomProperties', 'groupId')
    origin = values.get('Specification-Vendor')
    if not origin:
        origin = values.get('Implementation-Vendor')
    
    # use pom properties over manifest info (if available)
    if group_id:
        origin = group_id

    pkg_value = {
        'name': artifact['name'],
        'specification-version': values.get('Specification-Version', "N/A"),
        'implementation-version': values.get('Implementation-Version', "N/A"),
        'maven-version': dig(artifact, 'metadata', 'pomProperties', 'version', default="N/A"),
        'origin': origin or "N/A",
        'location': pkg_key, # this should be related to full path
        'type': "java-" + java_ext,
    }

    # inject the artifact document into the "raw" analyzer document
    findings['package_list']['pkgs.java']['base'][pkg_key] = pkg_value


def handle_python(findings, artifact):
    """Python results handler for syft output.

    Args:
        findings (dict): nested dictionary representing a json structure.
        artifact (json): datastructure presented by syft.

    Returns:
        dict: findings dictionary is populated with values from the provided
              artifact.
    """

    if "python-package-cataloger" not in artifact['foundBy']:
        # engine only includes python findings for egg and wheel installations (with rich metadata)
        return

    site_pkg_root = artifact['metadata']['sitePackagesRootPath']

    # anchore engine always uses the name, however, the name may not be a top-level package
    # instead default to the first top-level package unless the name is listed among the
    # top level packages explicitly defined in the metadata
    pkg_key_name = artifact['metadata']['topLevelPackages'][0]
    if artifact['name'] in artifact['metadata']['topLevelPackages']:
        pkg_key_name = artifact['name']

    pkg_key = os.path.join(site_pkg_root, pkg_key_name)
    origin = artifact['metadata'].get('author', "")
    email = artifact['metadata'].get('authorEmail', None)
    if email:
        origin += " <%s>" % email

    files = []
    for file in artifact['metadata'].get('files', []):
        files.append(os.path.join(site_pkg_root, file['path']))

    # craft the artifact document
    pkg_value = {
            'name': artifact['name'],
            'version': artifact['version'],
            'latest': artifact['version'],
            'files': files,
            'origin': origin,
            'license': artifact['metadata'].get('license', ""),
            'location': site_pkg_root,
            'type': 'python',
        }

    # inject the artifact document into the "raw" analyzer document
    findings['package_list']['pkgs.python']['base'][pkg_key] = pkg_value


def handle_gem(findings, artifact):
    """Gem results handler for syft output.

    Args:
        findings (dict): nested dictionary representing a json structure.
        artifact (json): datastructure presented by syft.

    Returns:
        dict: findings dictionary is populated with values from the provided
              artifact.
    """

    pkg_key = artifact['locations'][0]['path']

    # craft the artifact document
    pkg_value = {
            'name': artifact['name'],
            'versions': [artifact['version']],
            'latest': artifact['version'],
            'sourcepkg': artifact['metadata'].get('homepage', ''),
            'files': artifact['metadata'].get('files', []),
            'origins': artifact['metadata'].get('authors', []),
            'lics': artifact['metadata'].get('licenses', []),
        }

    # inject the artifact document into the "raw" analyzer document
    findings['package_list']['pkgs.gems']['base'][pkg_key] = pkg_value


def handle_npm(findings, artifact):
    """Javascript results handler for syft output.

    Args:
        findings (dict): nested dictionary representing a json structure.
        artifact (json): datastructure presented by syft.

    Returns:
        dict: findings dictionary is populated with values from the provided
              artifact.
    """

    pkg_key = artifact['locations'][0]['path']
    homepage = artifact['metadata'].get('homepage', '')
    author = artifact['metadata'].get('author')
    authors = artifact['metadata'].get('authors', [])
    origins = [] if not author else [author]
    origins.extend(authors)

    pkg_value = {
            'name': artifact['name'],
            'versions': [artifact['version']],
            'latest': artifact['version'],
            'sourcepkg': artifact['metadata'].get('url', homepage),
            'origins': origins,
            'lics': artifact['metadata'].get('licenses', []),
        }

    # inject the artifact document into the "raw" analyzer document
    findings['package_list']['pkgs.npms']['base'][pkg_key] = pkg_value


def filter_artifacts(artifact):
    """Filter Artifacts 
    
    helper function which only allow artifacts which have handlers 
    implemented, ignore the rest

    Args:
        artifact (json): datastructure presented by syft.

    Returns:
        str: keyword value used to determine the dispatch function.
    """
    
    return artifact['type'] in ARTIFACT_HANDLER_DISPATCH


def catalog_image(image):
    """Catalog image transforms syft output into "raw" analyzer
    json document then takes a sub-set of the findings and invokes the
    corrisponding handler to build specific json document.


    Args:
        image (str): container image name.

    Returns:
        dict: dictionary structure which represents the json data.
    """
    
    all_results = run_syft(image)

    # transform output into analyzer-module/service "raw" analyzer json document
    nested_dict = lambda: collections.defaultdict(nested_dict)
    findings = nested_dict()

    # take a sub-set of the syft findings and invoke the handler function to
    # craft the artifact document and inject into the "raw" analyzer json
    # document
    for artifact in filter(filter_artifacts, all_results['artifacts']):
        ARTIFACT_HANDLER_DISPATCH[artifact['type']](findings, artifact)

    return defaultdict_to_dict(findings)

ARTIFACT_HANDLER_DISPATCH = {
    'gem': handle_gem,
    'python': handle_python,
    'npm': handle_npm,
    'java-archive': handle_java,
    'jenkins-plugin': handle_java,
}