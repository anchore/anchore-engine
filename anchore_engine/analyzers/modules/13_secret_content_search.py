#!/usr/bin/env python3

import base64
import sys
import os
import re
import json
import tarfile

import anchore_engine.analyzers.utils

analyzer_name = "secret_content_search"

try:
    config = anchore_engine.analyzers.utils.init_analyzer_cmdline(
        sys.argv, analyzer_name
    )
except Exception as err:
    print(str(err))
    sys.exit(1)

imgname = config["imgid"]
imageId = config["imgid_full"]
unpackdir = config["dirs"]["unpackdir"]
rootfsdir = "/".join([unpackdir, "rootfs"])

sub_analyzer_names = ["secret_search", "content_search"]

matchparams = {}
regexps = {}
params = {}
results = {}
outputdirs = {}

for sub_analyzer_name in sub_analyzer_names:
    params[sub_analyzer_name] = {"maxfilesize": False}
    results[sub_analyzer_name] = {}
    regexps[sub_analyzer_name] = []
    matchparams[sub_analyzer_name] = []

    try:
        sub_config = anchore_engine.analyzers.utils.init_analyzer_cmdline(
            sys.argv, sub_analyzer_name
        )
    except Exception as err:
        print(str(err))
        sys.exit(1)

    outputdirs[sub_analyzer_name] = sub_config["dirs"]["outputdir"]

    if "analyzer_config" in sub_config and sub_config["analyzer_config"]:
        if (
            "regexp_match" in sub_config["analyzer_config"]
            and type(sub_config["analyzer_config"]["regexp_match"]) == list
        ):
            regexps[sub_analyzer_name] = sub_config["analyzer_config"]["regexp_match"]
        if (
            "match_params" in sub_config["analyzer_config"]
            and type(sub_config["analyzer_config"]["match_params"]) == list
        ):
            matchparams[sub_analyzer_name] = sub_config["analyzer_config"][
                "match_params"
            ]

        if matchparams.get(sub_analyzer_name, []):
            for param in matchparams[sub_analyzer_name]:
                try:
                    (key, value) = param.split("=")
                    if key == "MAXFILESIZE":
                        params[sub_analyzer_name]["maxfilesize"] = int(value)

                except:
                    print(
                        "WARN: could not parse parameter (should be 'key=value'), ignoring: "
                        + str(param)
                    )

skip = True
for sub_analyzer_name in sub_analyzer_names:
    if len(regexps[sub_analyzer_name]) > 0:
        skip = False
        break

if skip:
    print(
        "No regexp configuration found in analyzer_config.yaml for analyzers in {}, skipping".format(
            sub_analyzer_names
        )
    )
    sys.exit(0)

outputdata = {}

with tarfile.open(
    os.path.join(unpackdir, "squashed.tar"), mode="r", format=tarfile.PAX_FORMAT
) as tfl:

    alltnames = tfl.getnames()
    alltfiles = {}
    for name in alltnames:
        alltfiles[name] = True

    memberhash = anchore_engine.analyzers.utils.get_memberhash(tfl)
    # for member in tfl.getmembers():
    for member in list(memberhash.values()):
        name = "/{}".format(member.name)
        if member.islnk() or member.issym():
            emember = anchore_engine.analyzers.utils._get_extractable_member(
                tfl,
                member,
                deref_symlink=True,
                alltfiles=alltfiles,
                memberhash=memberhash,
            )
            if emember:
                member = emember

        if member.isreg():
            for sub_analyzer_name in sub_analyzer_names:
                dochecks = True

                if (
                    params[sub_analyzer_name]["maxfilesize"]
                    and int(member.size) > params[sub_analyzer_name]["maxfilesize"]
                ):
                    dochecks = False

                if not regexps[sub_analyzer_name]:
                    dochecks = False

                if dochecks:
                    with tfl.extractfile(member) as FH:
                        lineno = 0
                        for line in FH.readlines():
                            for regexp in regexps[sub_analyzer_name]:
                                try:
                                    regexpname, theregexp = regexp.split("=", 1)
                                except:
                                    theregexp = regexp

                                try:
                                    patt = re.match(theregexp.encode("utf-8"), line)
                                    if patt:
                                        b64regexp = str(
                                            base64.encodebytes(regexp.encode("utf-8")),
                                            "utf-8",
                                        )
                                        if name not in results[sub_analyzer_name]:
                                            results[sub_analyzer_name][name] = {}
                                        if (
                                            b64regexp
                                            not in results[sub_analyzer_name][name]
                                        ):
                                            results[sub_analyzer_name][name][
                                                b64regexp
                                            ] = list()
                                        results[sub_analyzer_name][name][
                                            b64regexp
                                        ].append(lineno)
                                except Exception as err:
                                    import traceback

                                    traceback.print_exc()
                                    print(
                                        "ERROR: configured regexp not valid or regexp cannot be applied - exception: "
                                        + str(err)
                                    )
                                    sys.exit(1)
                            lineno += 1
                else:
                    # skipping this file because maxfilesize is set and file is larger
                    pass

for sub_analyzer_name in sub_analyzer_names:
    outputdata = {}
    for name in list(results[sub_analyzer_name].keys()):
        buf = json.dumps(results[sub_analyzer_name][name])
        outputdata[name] = buf

    if outputdata:
        ofile = os.path.join(outputdirs[sub_analyzer_name], "regexp_matches.all")
        anchore_engine.analyzers.utils.write_kvfile_fromdict(ofile, outputdata)

sys.exit(0)
