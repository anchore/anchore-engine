import json
import os
import re
import tempfile

from anchore_engine.utils import run_command, run_command_list, manifest_to_digest
from anchore_engine.subsys import logger

def manifest_to_digest_shellout(rawmanifest):
    ret = None
    tmpmanifest = None
    try:
        fd,tmpmanifest = tempfile.mkstemp()
        os.write(fd, rawmanifest)
        os.close(fd)

        cmd = "skopeo manifest-digest {}".format(tmpmanifest)
        rc, sout, serr = run_command(cmd)
        if rc == 0 and re.match("^sha256:.*", sout):
            ret = sout.strip()
        else:
            logger.warn("failed to calculate digest from schema v1 manifest: cmd={} rc={} sout={} serr={}".format(cmd, rc, sout, serr))
            raise Exception("failed to calculate digest from schema v1 manifest")
    except Exception as err:
        raise err
    finally:
        if tmpmanifest:
            os.remove(tmpmanifest)

    return(ret)

def download_image(fulltag, copydir, user=None, pw=None, verify=True, manifest=None, use_cache_dir=None, dest_type='oci'):
    try:
        proc_env = os.environ.copy()
        if user and pw:
            proc_env['SKOPUSER'] = user
            proc_env['SKOPPASS'] = pw
            credstr = '--src-creds \"${SKOPUSER}\":\"${SKOPPASS}\"'
        else:
            credstr = ""

        if verify:
            tlsverifystr = "--src-tls-verify=true"
        else:
            tlsverifystr = "--src-tls-verify=false"

        if use_cache_dir and os.path.exists(use_cache_dir):
            cachestr = "--dest-shared-blob-dir " + use_cache_dir
        else:
            cachestr = ""

        if dest_type == 'oci':
            if manifest:
                with open(os.path.join(copydir, "manifest.json"), 'w') as OFH:
                    OFH.write(manifest)
            cmd = ["/bin/sh", "-c", "skopeo copy {} {} {} docker://{} oci:{}:image".format(tlsverifystr, credstr, cachestr, fulltag, copydir)]
        else:
            cmd = ["/bin/sh", "-c", "skopeo copy {} {} docker://{} dir:{}".format(tlsverifystr, credstr, fulltag, copydir)]

        cmdstr = ' '.join(cmd)
        try:
            rc, sout, serr = run_command_list(cmd, env=proc_env)
            if rc != 0:
                raise Exception("command failed: cmd="+str(cmdstr)+" exitcode="+str(rc)+" stdout="+str(sout).strip()+" stderr="+str(serr).strip())
            else:
                logger.debug("command succeeded: cmd="+str(cmdstr)+" stdout="+str(sout).strip()+" stderr="+str(serr).strip())

        except Exception as err:
            logger.error("command failed with exception - " + str(err))
            raise err
    except Exception as err:
        raise err

    return(True)

def get_repo_tags_skopeo(url, registry, repo, user=None, pw=None, verify=None, lookuptag=None):
    try:
        proc_env = os.environ.copy()
        if user and pw:
            proc_env['SKOPUSER'] = user
            proc_env['SKOPPASS'] = pw
            credstr = '--creds \"${SKOPUSER}\":\"${SKOPPASS}\"'
        else:
            credstr = ""

        if verify:
            tlsverifystr = "--tls-verify=true"
        else:
            tlsverifystr = "--tls-verify=false"
            
        pullstring = registry + "/" + repo
        if lookuptag:
            pullstring = pullstring + ":" + lookuptag

        repotags = []

        cmd = ["/bin/sh", "-c", "skopeo inspect {} {} docker://{}".format(tlsverifystr, credstr, pullstring)]
        cmdstr = ' '.join(cmd)
        try:
            rc, sout, serr = run_command_list(cmd, env=proc_env)
            if rc != 0:
                raise Exception("command failed: cmd="+str(cmdstr)+" exitcode="+str(rc)+" stdout="+str(sout).strip()+" stderr="+str(serr).strip())
            else:
                logger.debug("command succeeded: cmd="+str(cmdstr)+" stdout="+str(sout).strip()+" stderr="+str(serr).strip())
        except Exception as err:
            logger.error("command failed with exception - " + str(err))
            raise err

        data = json.loads(sout)
        repotags = data.get('RepoTags', [])
    except Exception as err:
        raise err

    if not repotags:
        raise Exception("no tags found for input repo from skopeo")

    return(repotags)

def get_image_manifest_skopeo(url, registry, repo, intag=None, indigest=None, user=None, pw=None, verify=True):
    manifest = {}
    digest = None
    testDigest = None

    if indigest:
        pullstring = registry + "/" + repo + "@" + indigest
    elif intag:
        pullstring = registry + "/" + repo + ":" + intag
    else:
        raise Exception("invalid input - must supply either an intag or indigest")

    try:
        proc_env = os.environ.copy()
        if user and pw:
            proc_env['SKOPUSER'] = user
            proc_env['SKOPPASS'] = pw
            credstr = '--creds \"${SKOPUSER}\":\"${SKOPPASS}\"'
        else:
            credstr = ""

        if verify:
            tlsverifystr = "--tls-verify=true"
        else:
            tlsverifystr = "--tls-verify=false"
            
        try:
            cmd = ["/bin/sh", "-c", "skopeo inspect --raw {} {} docker://{}".format(tlsverifystr, credstr, pullstring)]
            cmdstr = ' '.join(cmd)
            try:
                rc, sout, serr = run_command_list(cmd, env=proc_env)
                if rc != 0:
                    err = Exception("command failed")
                    err.cmd = "{}".format(cmdstr)
                    err.exitcode = "{}".format(rc)
                    err.sout = "{}".format(sout)
                    err.serr = "{}".format(serr)
                    raise err
                else:
                    logger.debug("command succeeded: cmd="+str(cmdstr)+" stdout="+str(sout).strip()+" stderr="+str(serr).strip())
            except Exception as err:
                logger.error("command failed with exception - " + str(err))
                raise err

            digest = manifest_to_digest(sout)
            manifest = json.loads(sout)

            if manifest.get('schemaVersion') == 2 and manifest.get('mediaType') == 'application/vnd.docker.distribution.manifest.list.v2+json':
                # Get the arch-specific version for amd64 and linux
                new_digest = None
                for entry in manifest.get('manifests'):
                    platform = entry.get('platform')
                    if platform and platform.get('architecture') in ['amd64'] and platform.get('os') == 'linux':
                        new_digest = entry.get('digest')
                        break

                return get_image_manifest_skopeo(url=url, registry=registry, repo=repo, intag=None, indigest=new_digest, user=user, pw=pw, verify=verify)
        except Exception as err:
            logger.warn("CMD failed - exception: " + str(err))
            errmsg = str(err)
            for k in ['sout', 'serr']:
                if k in err.__dict__:
                    errmsg = errmsg + " ({})".format(err.__dict__[k])

            raise Exception(errmsg)
            digest = None
            manifest = {}

    except Exception as err:
        raise err

    if not manifest or not digest:
        raise Exception("no digest/manifest from skopeo")

    return(manifest, digest)


