#!/usr/bin/env python3

import os
import sys
import json
import collections

import anchore_engine.analyzers.utils
from anchore_engine.clients.syft_wrapper import run_syft


def handle_gem(findings, artifact):
    pkg_key = artifact['locations'][0]['path']

    pkg_value = {
            'name': artifact['name'],
            'versions': [artifact['version']],
            'latest': artifact['version'],
            'sourcepkg': artifact['name'],
            'files': [], # TODO enhance
            'origins': [],
            'lics': [], # TODO enhance
        }

    findings['package_list']['pkgs.gems']['base'][pkg_key] = pkg_value

def filter_artifacts(artifact):
    # TODO: allow for more types as we go
    if artifact['type'] in ['bundle']:
        return True
    return False

def catalog_image(image):
    all_results = run_syft(image)
    partial_results = filter(filter_artifacts, all_results['artifacts'])

    indexLookup = {
        "gem": "pkgs.gems",
        # TODO: add indexes from analyzer file names as needed
    }

    handlerLookup = {
        'gem': handle_gem,
        # TODO: add handlers as we go...
    }

    typeLookup = {
        'bundle': 'gem',
        # TODO: map all of the types out here...
    }

    # transform output into analyzer-module/service json doc
    nested_dict = lambda: collections.defaultdict(nested_dict)
    findings = nested_dict()
    for artifact in partial_results:
        artifact_type = artifact['type']
        engine_type = typeLookup[artifact_type]

        handlerLookup[engine_type](findings, artifact)

    return defaultdict_to_dict(findings)

def defaultdict_to_dict(d):
    if isinstance(d, collections.defaultdict):
        d = {k: defaultdict_to_dict(v) for k, v in d.items()}
    return d


# def write_results(results, output_dir):
#     # write out results
#     output_file = os.path.join(output_dir, 'syft_packages')
#     anchore_engine.analyzers.utils.write_kvfile_fromdict(output_file, results)

# def main(image_path, output_dir):
#     results = run_syft_cataloger(image_path)
#     if results:
#         write_results(results, output_dir)
#     else:
#         print("no results")

# if __name__ == "__main__":

#     try:
#         config = engine_type.analyzers.utils.init_analyzer_cmdline(sys.argv, "syft_cataloger")
#     except Exception as err:
#         # TODO: improve me
#         print(str(err))
#         sys.exit(1)

#     image_path = config['dirs']['copydir']
#     output_dir = config['dirs']['outputdir']

#     main(image_path, output_dir)

# # main(sys.argv[1], ".")
