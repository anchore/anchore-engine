#!/usr/bin/python

import subprocess
import json
import time
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

precmd = "docker exec " + str(aecontainer) + " anchore-cli --json --u admin --p foobar --url http://localhost:8228/v1 "
#precmd = "anchore-cli --json --u admin --p foobar --url https://localhost:80/v1 --insecure "

reg = user = pw = None
try:
    reg = str(sys.argv[3])
    user = str(sys.argv[4])
    pw = str(sys.argv[5])
except:
    pass

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

    return(result)

result = aecmd("image list")

if reg and user and pw:
    print("adding registry " + reg + " : " + user + " ****")
    try:
        result = aecmd("registry add " + reg + " " + user + " " + pw)
        print("success adding registry")
    except:
        print("failed to add registry")
        sys.exit(1)

print("adding "+image+"")
result = aecmd("image add "+image+"")

timer = time.time()
done=False
for i in range(0, analysis_maxtime):
    results = aecmd("image get "+image+"")
    for result in results:
        print("current analysis_status: " + result['analysis_status'])
        if result['analysis_status'] == 'analyzed':
            print("\timage analyzed")
            done = True
            break
        elif result['analysis_status'] == 'analysis_failed':
            print("\timage failed to analyse (analysis_failed)")
            sys.exit(1)

    if done:
        break
    time.sleep(1)

if not done:
    print("timed out waiting for image to analyze")
    sys.exit(1)

print("image analyzed - total time: " + str(time.time() - timer))

if reg:
    try:
        result = aecmd("registry del " + reg)
        print("success deleting registry")
    except:
        print("failed to del registry")
        sys.exit(1)

try:
    result = aecmd("subscription activate tag_update "+image+"")
    result = aecmd("subscription activate policy_eval "+image+"")
    result = aecmd("subscription activate vuln_update "+image+"")
    print("activated subscriptions")

except Exception as err:
    print("unable to activate subscriptions")
    sys.exit(1)


done=False
for i in range(0, common_maxtime):
    try:
        result = aecmd("evaluate check "+image+" --tag "+image+"")
        if not result:
            raise Exception("no result")
        print("EVAL RESULT: " + json.dumps(result, indent=4))
        done=True
        break
    except Exception as err:
        try:
            if err.output:
                peval = json.loads(err.output)
                evala = peval[0]
                imageDigest = list(evala.keys())[0]
                fulltag = list(evala[imageDigest].keys())[0]
                evalb = evala[imageDigest][fulltag][0]
                status = evalb['status']
                print("STATUS: " + status)
                done = True
                break
        except:
            pass
        print("policy eval not ready yet: " + str(err))
    time.sleep(1)

if not done:
    print("unable to get valid policy eval")
    sys.exit(1)

done=False
for i in range(0, common_maxtime):
    try:
        result = aecmd("image del "+image+"")
        print("was able to delete latest/subscribed image (incorrect)")
        sys.exit(1)
    except:
        print("could not delete latest/subscribed image (correct)")

    try:
        result = aecmd("subscription deactivate tag_update "+image+"")
        result = aecmd("subscription deactivate policy_eval "+image+"")
        result = aecmd("subscription deactivate vuln_update "+image+"")
        result = aecmd("subscription deactivate analysis_update "+image+"")
        result = aecmd("image del "+image+"")

        print("was able to delete latest/unsubscribed image (correct)")
        done = True
        break
    except Exception as err:
        print("could not delete latest/unsubscribed image (incorrect): " + str(err))

if not done:
    print("unable to deactivate/delete image")
    sys.exit(1)

sys.exit(0)
