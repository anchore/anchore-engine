import json
import os
import subprocess

from anchore_engine.subsys import logger

def download_image(fulltag, copydir, user=None, pw=None, verify=True):
    try:
        if user and pw:
            os.environ['SKOPUSER'] = user
            os.environ['SKOPPASS'] = pw
            credstr = "--src-creds ${SKOPUSER}:${SKOPPASS}"
            credstr = "--src-creds " + user + ":" + pw
        else:
            credstr = ""

        if verify:
            tlsverifystr = "--src-tls-verify=true"
        else:
            tlsverifystr = "--src-tls-verify=false"
            
        #dlcmd = "skopeo copy docker://"+fulltag+" dir:"+copydir
        cmdstr = "skopeo copy "+tlsverifystr+" "+credstr+" docker://"+fulltag+" dir:"+copydir
        logger.debug("\tDLCMD: " + str(cmdstr))
        sout = subprocess.check_output(cmdstr.split())
    except Exception as err:
        raise err
    finally:
        try:
            del os.environ['SKOPUSER']
        except:
            pass
        try:
            del os.environ['SKOPPASS']
        except:
            pass

    return(True)

def get_image_manifest_skopeo(url, registry, repo, tag, user=None, pw=None, verify=True):
    manifest = {}
    digest = None

    try:
        if user and pw:
            os.environ['SKOPUSER'] = user
            os.environ['SKOPPASS'] = pw
            credstr = "--creds ${SKOPUSER}:${SKOPPASS}"
            credstr = "--creds " + user + ":" + pw
        else:
            credstr = ""

        if verify:
            tlsverifystr = "--tls-verify=true"
        else:
            tlsverifystr = "--tls-verify=false"
            

        try:
            cmdstr = "skopeo inspect --raw "+tlsverifystr+" "+credstr+" docker://"+registry+"/"+repo+":"+tag
            cmd = cmdstr.split()
            sout = subprocess.check_output(cmd)
            manifest = json.loads(sout)
        except Exception as err:
            logger.warn("CMD failed - exception: " + str(err))
            manifest = {}

        try:
            cmdstr = "skopeo inspect "+tlsverifystr+" "+credstr+" docker://"+registry+"/"+repo+":"+tag
            cmd = cmdstr.split()
            sout = subprocess.check_output(cmd)
            skopeo_output = sout
            data = json.loads(skopeo_output)
            digest = data['Digest']
        except Exception as err:
            logger.warn("CMD failed - exception: " + str(err))
            digest = None

    except Exception as err:
        #logger.error("error in skopeo wrapper - exception: " + str(err))
        raise err
    finally:
        try:
            del os.environ['SKOPUSER']
        except:
            pass
        try:
            del os.environ['SKOPPASS']
        except:
            pass

    if not manifest or not digest:
        raise Exception("no digest/manifest from skopeo")

    return(manifest, digest)


