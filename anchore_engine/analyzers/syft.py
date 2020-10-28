#!/usr/bin/env python3

import os
import collections

import anchore_engine.analyzers.utils
from anchore_engine.clients.syft_wrapper import run_syft


def dig(target, *keys, **kwargs):
    """
    Traverse a nested set of dictionaries, tuples, or lists similar to ruby's dig function.
    """
    end_of_chain = target
    for key in keys:
        if isinstance(end_of_chain, dict) and key in end_of_chain:
            end_of_chain = end_of_chain[key]
        elif isinstance(end_of_chain, (list, tuple)) and isinstance(key, int):
            end_of_chain = end_of_chain[key]
        else:
            if 'fail' in kwargs and kwargs['fail'] is True:
                if isinstance(end_of_chain, dict):
                    raise KeyError
                else:
                    raise IndexError
            elif 'default' in kwargs:
                return kwargs['default']
            else:
                return None

    return end_of_chain


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
    java_ext = pkg_key.split(".")[-1]
    maven_version = dig(artifact, 'metadata', 'pomProperties', 'version', default="N/A")

    spec_vendor = dig(artifact, 'metadata', 'manifest', 'main', 'Specification-Vendor')
    implem_vendor = dig(artifact, 'metadata', 'manifest', 'main', 'Implementation-Vendor')

    if spec_vendor:
        origin = spec_vendor
    elif implem_vendor:
        origin = implem_vendor
    else:
        origin = dig(artifact, 'metadata', 'pomProperties', 'groupId', default="N/A")
    
    pkg_value = {
        'name': artifact['name'],
        'specification-version': dig(artifact, 'metadata', 'manifest', 'main', 'Specification-Version', default="N/A"),
        'implementation-version': dig(artifact, 'metadata', 'manifest', 'main', 'Implementation-Version', default="N/A"),
        'maven-version': maven_version,
        'origin': origin,
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

    return anchore_engine.analyzers.utils.defaultdict_to_dict(findings)

ARTIFACT_HANDLER_DISPATCH = {
    'gem': handle_gem,
    'python': handle_python,
    'npm': handle_npm,
    'java-archive': handle_java,
    'jenkins-plugin': handle_java,
}