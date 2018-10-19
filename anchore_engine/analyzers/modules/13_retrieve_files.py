#!/usr/bin/env python3

import base64
import sys
import os
import re
import json

import anchore_engine.analyzers.utils

analyzer_name = "retrieve_files"

try:
    config = anchore_engine.analyzers.utils.init_analyzer_cmdline(sys.argv, analyzer_name)
except Exception as err:
    print(str(err))
    sys.exit(1)

imgname = config['imgid']
imageId = config['imgid_full']
outputdir = config['dirs']['outputdir']
unpackdir = config['dirs']['unpackdir']
rootfsdir = '/'.join([unpackdir, 'rootfs'])

files_to_store = list()
if 'analyzer_config' in config and config['analyzer_config']:
    if 'file_list' in config['analyzer_config']  and type(config['analyzer_config']['file_list']) == list:
        files_to_store = config['analyzer_config']['file_list']

if len(files_to_store) <= 0:
    print("No file_list configuration found in analyzer_config.yaml for analyzer '"+analyzer_name+", skipping")
    sys.exit(0)

outputdata = {}
for name in files_to_store:
    thefile = '/'.join([rootfsdir, name])
    if os.path.isfile(thefile):
        b64buf = ""
        try:
            with open(thefile, 'r') as FH:
                buf = FH.read()
                b64buf = str(base64.b64encode(buf.encode('utf-8')), 'utf-8')
            outputdata[name] = b64buf
        except Exception as err:
            print ("WARN: exception while reading/encoding file {} - exception: {}".format(name, err))

if outputdata:
    ofile = os.path.join(outputdir, 'file_content.all')
    anchore_engine.analyzers.utils.write_kvfile_fromdict(ofile, outputdata)

sys.exit(0)
