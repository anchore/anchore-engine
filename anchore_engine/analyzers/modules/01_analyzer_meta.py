#!/usr/bin/env python

import sys
import os
import shutil
import re
import json
import time
import subprocess
import anchore.anchore_utils

analyzer_name = "analyzer_meta"

try:
    config = anchore.anchore_utils.init_analyzer_cmdline(sys.argv, analyzer_name)
except Exception as err:
    print str(err)
    sys.exit(1)

imgname = config['imgid']
outputdir = config['dirs']['outputdir']
unpackdir = config['dirs']['unpackdir']

try:
    meta = anchore.anchore_utils.get_distro_from_path(os.path.join(unpackdir, "rootfs"))

    dockerfile_contents = None
    if os.path.exists(os.path.join(unpackdir, "Dockerfile")):
        dockerfile_contents = anchore.anchore_utils.read_plainfile_tostr(os.path.join(unpackdir, "Dockerfile"))

    if meta:
        ofile = os.path.join(outputdir, 'analyzer_meta')
        anchore.anchore_utils.write_kvfile_fromdict(ofile, meta)
        shutil.copy(ofile, unpackdir + "/analyzer_meta")
    else:
        raise Exception("could not analyze/store basic metadata about image")

    if dockerfile_contents:
        ofile = os.path.join(outputdir, 'Dockerfile')
        anchore.anchore_utils.write_plainfile_fromstr(ofile, dockerfile_contents)

except Exception as err:
    raise err

sys.exit(0)


