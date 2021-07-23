#!/usr/bin/python

import json
import subprocess
import sys

analysis_maxtime = 900
common_maxtime = 60

try:
    image = str(sys.argv[1])
except:
    image = "docker.io/alpine:latest"

try:
    aecontainer = str(sys.argv[2])
except:
    aecontainer = "qadc_anchore-engine_1"

# precmd = "docker exec " + str(aecontainer) + " anchore-cli --json --u admin --p foobar --url http://localhost:8228/v1 "
precmd = "anchore-cli --json --u admin --p foobar --url http://localhost:8228/v1 "


def aecmd(cmd):
    global precmd
    cmdstr = precmd + cmd
    try:
        print("COMMAND: " + str(cmdstr))
        result = json.loads(subprocess.check_output(cmdstr.split()))
    except Exception as err:
        try:
            print("err response: " + str(err.output))
            result = json.loads(err.output)
        except:
            pass
        raise err

    return result


result = aecmd("image list")

badimage = "foobarbarfoo"
regimage = "container-registry.oracle.com/os/oraclelinux:latest"

print("adding " + badimage + "")
try:
    result = aecmd("image add " + badimage + "")
    print("success adding bad image (incorrect)")
    sys.exit(1)
except:
    print("failed to add bad image (correct)")

print("checking " + badimage + "")
try:
    result = aecmd("evaluate check " + badimage)
    print("success evaling bad image (incorrect)")
    sys.exit(1)
except:
    print("failed to eval bad image (correct)")

print("subscribing " + badimage + "")

try:
    result = aecmd("subscription activate tag_update " + badimage)
    print("success subscribing bad image (incorrect)")
    sys.exit(1)
except:
    print("failed to subscribe bad image (correct)")

print("adding unauth registry image " + regimage)
try:
    result = aecmd("image add container-registry.oracle.com/os/oraclelinux:latest")
    print("success adding oracle registry image as anon (incorrect)")
    sys.exit(1)
except:
    print("failed adding oracle registry image as anon (correct)")

print("all failure cases passed")
sys.exit(0)
