#!/usr/bin/env python3

import base64
import os
import re
import sys
import tarfile

import anchore_engine.analyzers.utils
import anchore_engine.utils

analyzer_name = "retrieve_files"

try:
    config = anchore_engine.analyzers.utils.init_analyzer_cmdline(
        sys.argv, analyzer_name
    )
except Exception as err:
    print(str(err))
    sys.exit(1)

imgname = config["imgid"]
imageId = config["imgid_full"]
outputdir = config["dirs"]["outputdir"]
unpackdir = config["dirs"]["unpackdir"]
rootfsdir = "/".join([unpackdir, "rootfs"])
max_file_size_bytes = -1

files_to_store = list()
if "analyzer_config" in config and config["analyzer_config"]:
    if (
        "file_list" in config["analyzer_config"]
        and type(config["analyzer_config"]["file_list"]) == list
    ):
        files_to_store = config["analyzer_config"]["file_list"]

    if (
        "max_file_size_kb" in config["analyzer_config"]
        and type(config["analyzer_config"]["max_file_size_kb"]) == int
    ):
        max_file_size_bytes = config["analyzer_config"]["max_file_size_kb"] * 1024


if len(files_to_store) <= 0:
    print(
        "No file_list configuration found in analyzer_config.yaml for analyzer '"
        + analyzer_name
        + ", skipping"
    )
    sys.exit(0)

outputdata = {}
with tarfile.open(
    os.path.join(unpackdir, "squashed.tar"), mode="r", format=tarfile.PAX_FORMAT
) as tfl:
    for name in files_to_store:
        thefile = re.sub("^/+", "", name)
        try:
            member = tfl.getmember(thefile)
        except:
            member = None

        if member and member.isreg():
            if max_file_size_bytes < 0 or member.size <= max_file_size_bytes:
                b64buf = ""
                try:
                    with tfl.extractfile(member) as FH:
                        buf = FH.read()
                        b64buf = anchore_engine.utils.ensure_str(base64.b64encode(buf))
                    outputdata[name] = b64buf
                except Exception as err:
                    print(
                        "WARN: exception while reading/encoding file {} - exception: {}".format(
                            name, err
                        )
                    )
            else:
                print(
                    "WARN: skipping file {} in file list due to size {} > max file size bytes of {}".format(
                        thefile, member.size, max_file_size_bytes
                    )
                )

if outputdata:
    ofile = os.path.join(outputdir, "file_content.all")
    anchore_engine.analyzers.utils.write_kvfile_fromdict(ofile, outputdata)

sys.exit(0)
