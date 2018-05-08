#!/usr/bin/env python

import sys
import os
import shutil
import re
import json
import time
import rpm
import subprocess
import tarfile

import anchore.anchore_utils

analyzer_name = "retrieve_files"

try:
    config = anchore.anchore_utils.init_analyzer_cmdline(sys.argv, analyzer_name)
except Exception as err:
    print str(err)
    sys.exit(1)

imgname = config['imgid']
imgid = config['imgid_full']
outputdir = config['dirs']['outputdir']
unpackdir = config['dirs']['unpackdir']
rootfsdir = '/'.join([unpackdir, 'rootfs'])

#if not os.path.exists(outputdir):
#    os.makedirs(outputdir)

files_to_get = list()
if 'analyzer_config' in config and config['analyzer_config']:
    if 'file_list' in config['analyzer_config']  and type(config['analyzer_config']['file_list']) == list:
        files_to_get = config['analyzer_config']['file_list']

if len(files_to_get) <= 0:
    print "No configuration found in analyzer_config.yaml for analyzer '"+analyzer_name+", skipping"
    sys.exit(0)

outputdata = {}
storefiles = list()
for f in files_to_get:
    thefile = '/'.join([unpackdir, 'rootfs', f])
    if os.path.exists(thefile):
        outputdata[f] = thefile
        storefiles.append(thefile)
    else:
        pass

try:
    anchore.anchore_utils.save_files(imgid, analyzer_name, rootfsdir, storefiles)
except Exception as err:
    print "ERROR: unable to store files - exception: " + str(err)
    outputdata = {}
    
if outputdata:
    ofile = os.path.join(outputdir, 'file_cache.all')
    anchore.anchore_utils.write_kvfile_fromdict(ofile, outputdata)

sys.exit(0)
