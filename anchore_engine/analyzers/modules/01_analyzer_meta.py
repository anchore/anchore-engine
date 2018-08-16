#!/usr/bin/env python3

import sys
import os
import shutil
import anchore_engine.analyzers.utils

analyzer_name = "analyzer_meta"

try:
    config = anchore_engine.analyzers.utils.init_analyzer_cmdline(sys.argv, analyzer_name)
except Exception as err:
    import traceback
    traceback.print_exc()
    print(str(err))
    sys.exit(1)

imgname = config['imgid']
outputdir = config['dirs']['outputdir']
unpackdir = config['dirs']['unpackdir']

try:
    meta = anchore_engine.analyzers.utils.get_distro_from_path(os.path.join(unpackdir, "rootfs"))

    dockerfile_contents = None
    if os.path.exists(os.path.join(unpackdir, "Dockerfile")):
        dockerfile_contents = anchore_engine.analyzers.utils.read_plainfile_tostr(os.path.join(unpackdir, "Dockerfile"))

    if meta:
        ofile = os.path.join(outputdir, 'analyzer_meta')
        anchore_engine.analyzers.utils.write_kvfile_fromdict(ofile, meta)
        shutil.copy(ofile, unpackdir + "/analyzer_meta")
    else:
        raise Exception("could not analyze/store basic metadata about image")

    if dockerfile_contents:
        ofile = os.path.join(outputdir, 'Dockerfile')
        anchore_engine.analyzers.utils.write_plainfile_fromstr(ofile, dockerfile_contents)

except Exception as err:
    raise err

sys.exit(0)


