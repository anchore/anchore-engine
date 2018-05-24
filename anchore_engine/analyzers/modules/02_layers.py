#!/usr/bin/env python3

import sys
import os
import re
import json

import anchore_engine.analyzers.utils

analyzer_name = "layer_info"

try:
    config = anchore_engine.analyzers.utils.init_analyzer_cmdline(sys.argv, analyzer_name)
except Exception as err:
    print(str(err))
    sys.exit(1)

imgname = config['imgid']
outputdir = config['dirs']['outputdir']
unpackdir = config['dirs']['unpackdir']

output = list()

try:
    hfile = os.path.join(unpackdir, "docker_history.json")
    if os.path.exists(hfile):
        with open(hfile, 'r') as FH:
            history = json.loads(FH.read())

        for record in history:
            clean_layer = re.sub("^sha256:", "", record['Id'])
            if clean_layer == '<missing>':
                clean_layer = "unknown"
                
            clean_createdBy = re.sub(r"^/bin/sh -c #\(nop\) ", "", record['CreatedBy'])
            line = {'layer':clean_layer, 'dockerfile_line':clean_createdBy, 'layer_sizebytes':str(record['Size'])}
            output.append(line)
    else:
        raise Exception("anchore failed to provide file '"+str(hfile)+"': cannot create layer info analyzer output")
except Exception as err:
    import traceback
    traceback.print_exc()
    raise err

ofile = os.path.join(outputdir, 'layers_to_dockerfile')
anchore_engine.analyzers.utils.write_kvfile_fromdict(ofile, {'dockerfile_to_layer_map':json.dumps(output)})

sys.exit(0)
