#!/usr/bin/env python3

import json
import os
import sys

import anchore_engine.analyzers.utils

analyzer_name = "package_list"

try:
    config = anchore_engine.analyzers.utils.init_analyzer_cmdline(
        sys.argv, analyzer_name
    )
except Exception as err:
    print(str(err))
    sys.exit(1)

imgname = config["imgid"]
imgid = config["imgid_full"]
outputdir = config["dirs"]["outputdir"]
unpackdir = config["dirs"]["unpackdir"]
squashtar = os.path.join(unpackdir, "squashed.tar")

go_package_el = {
    "name": None,
    "version": None,
    "location": None,
    "type": "go",
    "files": [],
    "license": "N/A",
    "origin": "N/A",
    "metadata": json.dumps({}),
}

resultlist = {}
try:
    allfiles = {}
    if os.path.exists(unpackdir + "/anchore_allfiles.json"):
        with open(unpackdir + "/anchore_allfiles.json", "r") as FH:
            allfiles = json.loads(FH.read())
    else:
        # fmap, allfiles = anchore_engine.analyzers.utils.get_files_from_path(unpackdir + "/rootfs")
        fmap, allfiles = anchore_engine.analyzers.utils.get_files_from_squashtar(
            os.path.join(unpackdir, "squashed.tar")
        )
        with open(unpackdir + "/anchore_allfiles.json", "w") as OFH:
            OFH.write(json.dumps(allfiles))

    try:
        squashtar = os.path.join(unpackdir, "squashed.tar")
        hints = anchore_engine.analyzers.utils.get_hintsfile(unpackdir, squashtar)
        for pkg in hints.get("packages", []):
            pkg_type = pkg.get("type", "").lower()

            if pkg_type == "go":
                try:
                    pkg_key, el = anchore_engine.analyzers.utils._hints_to_go(pkg)
                    try:
                        resultlist[pkg_key] = json.dumps(el)
                    except Exception as err:
                        print(
                            "WARN: unable to add go package ({}) from hints - excpetion: {}".format(
                                pkg_key, err
                            )
                        )
                except Exception as err:
                    print(
                        "WARN: bad hints record encountered - exception: {}".format(err)
                    )
    except Exception as err:
        print("WARN: problem honoring hints file - exception: {}".format(err))

except Exception as err:
    import traceback

    traceback.print_exc()
    print("WARN: analyzer unable to complete - exception: " + str(err))

if resultlist:
    ofile = os.path.join(outputdir, "pkgs.go")
    anchore_engine.analyzers.utils.write_kvfile_fromdict(ofile, resultlist)

sys.exit(0)
