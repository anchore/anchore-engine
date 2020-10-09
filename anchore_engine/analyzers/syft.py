#!/usr/bin/env python3

import os
import sys
import json
import collections

import anchore_engine.analyzers.utils
from anchore_engine.clients.syft_wrapper import run_syft


def handle_gem(findings, artifact):
    pkg_key = artifact['locations'][0]['path']

    # craft the artifact document
    pkg_value = {
            'name': artifact['name'],
            'versions': [artifact['version']],
            'latest': artifact['version'],
            'sourcepkg': artifact['name'],
            'files': artifact['metadata'].get('files', []) or [],
            'origins': [],
            'lics': artifact['metadata'].get('licenses', []) or [],
        }

    # inject the artifact document into the "raw" analyzer document
    findings['package_list']['pkgs.gems']['base'][pkg_key] = pkg_value

def filter_artifacts(artifact):
    # only allow artifacts which have handlers implemented, ignore the rest
    return artifact['type'] in artifact_handler_dispatch.keys()

def catalog_image(image):
    all_results = run_syft(image)

    # transform output into analyzer-module/service "raw" analyzer json document
    nested_dict = lambda: collections.defaultdict(nested_dict)
    findings = nested_dict()

    # take a sub-set of the syft findings and invoke the handler function to craft the artifact document and inject into the "raw" analyzer json document
    for artifact in filter(filter_artifacts, all_results['artifacts']):
        artifact_handler_dispatch[artifact['type']](findings, artifact)

    return anchore_engine.analyzers.utils.defaultdict_to_dict(findings)


artifact_handler_dispatch = {
    'gem': handle_gem,
    # TODO: add handlers as we go...
}