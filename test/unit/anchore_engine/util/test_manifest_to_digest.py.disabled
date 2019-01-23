import subprocess
import unittest
import json
import os
import re

from anchore_engine.utils import manifest_to_digest, ensure_str
from anchore_engine.clients.skopeo_wrapper import manifest_to_digest_shellout, get_image_manifest_skopeo_raw, get_image_manifest_skopeo

def _load_test_manifests():
    manifests = {}
    digests = {}
    mdir = "./test/unit/data/example_raw_manifests"
    for fname in os.listdir(mdir):
        if re.match(".*{}$".format(re.escape(".json")), fname):
            with open(os.path.join(mdir, fname), 'r') as FH:
                manifests[fname] = FH.read()
            with open(os.path.join(mdir, "{}.digest".format(fname)), 'r') as FH:
                digests[fname] = FH.read().strip()

    return(manifests, digests)

# test to determine if skopeo computed digest from manifest is equal to anchore manifest-to-digest computed digest
def test_manifest_to_digest():

    registries = ['docker.io']
    repos = ['alpine']
    tags = ['latest']

    manifests_to_check, digests_to_check = _load_test_manifests()

    for fname in manifests_to_check.keys():
        rawmanifest = manifests_to_check[fname]
        anchore_digest = ensure_str(manifest_to_digest(rawmanifest))
        #skopeo_digest = ensure_str(manifest_to_digest_shellout(rawmanifest))
        skopeo_digest = digests_to_check[fname]

        print ("TESTING ({}): anchore_digest({}) == skopeo_digest({})".format(fname, anchore_digest, skopeo_digest))
        print ("\tRESULT: {}".format(anchore_digest == skopeo_digest))
        assert(anchore_digest == skopeo_digest)
