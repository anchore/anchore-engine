#!/usr/bin/env python3

import os
import collections

from anchore_engine.analyzers.utils import defaultdict_to_dict
from anchore_engine.clients.syft_wrapper import run_syft
from .handlers import handlers_by_artifact_type


def filter_artifacts(artifact):
    return artifact['type'] in handlers_by_artifact_type

def catalog_image(image):
    """
    Catalog the given image with syft, keeping only select artifacts in the returned results.
    """
    all_results = run_syft(image)

    # transform output into analyzer-module/service "raw" analyzer json document
    nested_dict = lambda: collections.defaultdict(nested_dict)
    findings = nested_dict()

    # take a sub-set of the syft findings and invoke the handler function to
    # craft the artifact document and inject into the "raw" analyzer json
    # document
    for artifact in filter(filter_artifacts, all_results['artifacts']):
        handler = handlers_by_artifact_type[artifact['type']]
        handler(findings, artifact)

    return defaultdict_to_dict(findings)

