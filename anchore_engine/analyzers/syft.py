#!/usr/bin/env python3

import os
import collections

import anchore_engine.analyzers.utils
from anchore_engine.clients.syft_wrapper import run_syft


def handle_python(findings, artifact):
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
    # only allow artifacts which have handlers implemented, ignore the rest
    return artifact['type'] in artifact_handler_dispatch


def catalog_image(image):
    all_results = run_syft(image)

    # transform output into analyzer-module/service "raw" analyzer json document
    nested_dict = lambda: collections.defaultdict(nested_dict)
    findings = nested_dict()

    # take a sub-set of the syft findings and invoke the handler function to
    # craft the artifact document and inject into the "raw" analyzer json
    # document
    for artifact in filter(filter_artifacts, all_results['artifacts']):
        artifact_handler_dispatch[artifact['type']](findings, artifact)

    return anchore_engine.analyzers.utils.defaultdict_to_dict(findings)


artifact_handler_dispatch = {
    'gem': handle_gem,
    'python': handle_python,
    'npm': handle_npm,
    # TODO: add handlers as we go...
}
