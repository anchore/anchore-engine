import json
import os
import re
import tempfile

import anchore_engine.configuration.localconfig
from anchore_engine.utils import run_command, run_command_list, manifest_to_digest, AnchoreException
from anchore_engine.subsys import logger
from anchore_engine.common.errors import AnchoreError

def manifest_to_digest_shellout(rawmanifest):
    ret = None
    tmpmanifest = None
    try:
        fd,tmpmanifest = tempfile.mkstemp()
        os.write(fd, rawmanifest.encode('utf-8'))
        os.close(fd)

        localconfig = anchore_engine.configuration.localconfig.get_config()
        global_timeout = localconfig.get('skopeo_global_timeout', 0)
        try:
            global_timeout = int(global_timeout)
            if global_timeout < 0:
                global_timeout = 0
        except:
            global_timeout = 0

        if global_timeout:
            global_timeout_str = "--command-timeout {}s".format(global_timeout)
        else:
            global_timeout_str = ""

        cmd = "skopeo {} manifest-digest {}".format(global_timeout_str, tmpmanifest)
        rc, sout, serr = run_command(cmd)
        if rc == 0 and re.match("^sha256:.*", str(sout, 'utf-8')):
            ret = sout.strip()
        else:
            logger.warn("failed to calculate digest from schema v1 manifest: cmd={} rc={} sout={} serr={}".format(cmd, rc, sout, serr))
            raise SkopeoError(cmd=cmd, rc=rc, err=serr, out=sout, msg='Failed to calculate digest from schema v1 manifest', )
    except Exception as err:
        raise err
    finally:
        if tmpmanifest:
            os.remove(tmpmanifest)

    return(ret)

def copy_image_from_docker_archive(source_archive, dest_dir):
    cmdstr = "skopeo copy docker-archive:{} oci:{}:image".format(source_archive, dest_dir)
    cmd = cmdstr.split()
    try:
        rc, sout, serr = run_command_list(cmd)
        if rc != 0:
            raise SkopeoError(cmd=cmd, rc=rc, out=sout, err=serr)
        else:
            logger.debug("command succeeded: cmd="+str(cmdstr)+" stdout="+str(sout).strip()+" stderr="+str(serr).strip())

    except Exception as err:
        logger.error("command failed with exception - " + str(err))
        raise err

def download_image(fulltag, copydir, user=None, pw=None, verify=True, manifest=None, parent_manifest=None, use_cache_dir=None, dest_type='oci'):
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

        localconfig = anchore_engine.configuration.localconfig.get_config()
        global_timeout = localconfig.get('skopeo_global_timeout', 0)
        try:
            global_timeout = int(global_timeout)
            if global_timeout < 0:
                global_timeout = 0
        except:
            global_timeout = 0

        if global_timeout:
            global_timeout_str = "--command-timeout {}s".format(global_timeout)
        else:
            global_timeout_str = ""

        os_overrides = [""]
        if manifest:
            manifest_data = json.loads(manifest)

            # skopeo doesn't support references in manifests for copy/download operations, with oci dest type - if found, override with dir dest_type
            for l in manifest_data.get('layers', []):
                if 'foreign.diff' in l.get('mediaType', ""):
                    dest_type = 'dir'

            if parent_manifest:
                parent_manifest_data = json.loads(parent_manifest)
            else:
                parent_manifest_data = {}

            if parent_manifest_data:
                for mlist in parent_manifest_data.get('manifests', []):
                    imageos = mlist.get('platform', {}).get('os', "")
                    if imageos not in ["", 'linux']:
                        # add a windows os override to the list of override attempts, to complete the options that are supported by skopeo
                        dest_type = 'dir'
                        os_overrides.insert(0, "windows")
                        break

        for os_override in os_overrides:
            success = False
            if os_override not in ["", 'linux']:
                dest_type = 'dir'
                os_override_str = "--override-os {}".format(os_override)
            else:
                os_override_str = ""
                
            if dest_type == 'oci':
                if manifest:
                    with open(os.path.join(copydir, "manifest.json"), 'w') as OFH:
                        OFH.write(manifest)

                if parent_manifest:
                    with open(os.path.join(copydir, "parent_manifest.json"), 'w') as OFH:
                        OFH.write(parent_manifest)
                        
                cmd = ["/bin/sh", "-c", "skopeo {} {} copy {} {} {} docker://{} oci:{}:image".format(os_override_str, global_timeout_str, tlsverifystr, credstr, cachestr, fulltag, copydir)]
            else:
                cmd = ["/bin/sh", "-c", "skopeo {} {} copy {} {} docker://{} dir:{}".format(os_override_str, global_timeout_str, tlsverifystr, credstr, fulltag, copydir)]

            cmdstr = ' '.join(cmd)
            try:
                rc, sout, serr = run_command_list(cmd, env=proc_env)
                if rc != 0:
                    skopeo_error = SkopeoError(cmd=cmd, rc=rc, out=sout, err=serr)
                    if skopeo_error.error_code != AnchoreError.OSARCH_MISMATCH.name:
                        raise SkopeoError(cmd=cmd, rc=rc, out=sout, err=serr)                    
                else:
                    logger.debug("command succeeded: cmd="+str(cmdstr)+" stdout="+str(sout).strip()+" stderr="+str(serr).strip())
                    success = True                    

            except Exception as err:
                logger.error("command failed with exception - " + str(err))
                raise err

            if success:
                break
        if not success:
            logger.error("could not download image")
            raise Exception("could not download image")
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
            
        localconfig = anchore_engine.configuration.localconfig.get_config()
        global_timeout = localconfig.get('skopeo_global_timeout', 0)
        try:
            global_timeout = int(global_timeout)
            if global_timeout < 0:
                global_timeout = 0
        except:
            global_timeout = 0

        if global_timeout:
            global_timeout_str = "--command-timeout {}s".format(global_timeout)
        else:
            global_timeout_str = ""

        pullstring = registry + "/" + repo
        if lookuptag:
            pullstring = pullstring + ":" + lookuptag

        repotags = []

        cmd = ["/bin/sh", "-c", "skopeo {} inspect {} {} docker://{}".format(global_timeout_str, tlsverifystr, credstr, pullstring)]
        cmdstr = ' '.join(cmd)
        try:
            rc, sout, serr = run_command_list(cmd, env=proc_env)
            sout = str(sout, 'utf-8') if sout else None
            if rc != 0:
                raise SkopeoError(cmd=cmd, rc=rc, out=sout, err=serr)
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

def get_image_manifest_skopeo_raw(pullstring, user=None, pw=None, verify=True):
    ret = None
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

        localconfig = anchore_engine.configuration.localconfig.get_config()
        global_timeout = localconfig.get('skopeo_global_timeout', 0)            
        try:
            global_timeout = int(global_timeout)
            if global_timeout < 0:
                global_timeout = 0
        except:
            global_timeout = 0

        if global_timeout:
            global_timeout_str = "--command-timeout {}s".format(global_timeout)
        else:
            global_timeout_str = ""

        os_override_strs = ["", "--override-os windows"]
        try:
            success = False
            for os_override_str in os_override_strs:
                cmd = ["/bin/sh", "-c", "skopeo {} {} inspect --raw {} {} docker://{}".format(global_timeout_str, os_override_str, tlsverifystr, credstr, pullstring)]
                cmdstr = ' '.join(cmd)
                try:
                    rc, sout, serr = run_command_list(cmd, env=proc_env)
                    if rc != 0:
                        skopeo_error = SkopeoError(cmd=cmd, rc=rc, out=sout, err=serr)
                        if skopeo_error.error_code != AnchoreError.OSARCH_MISMATCH.name:
                            raise SkopeoError(cmd=cmd, rc=rc, out=sout, err=serr)
                    else:
                        logger.debug("command succeeded: cmd="+str(cmdstr)+" stdout="+str(sout).strip()+" stderr="+str(serr).strip())
                        success = True
                except Exception as err:
                    logger.error("command failed with exception - " + str(err))
                    raise err

                if success:
                    sout = str(sout, 'utf-8') if sout else None    
                    ret = sout
                    break

            if not success:
                logger.error("could not retrieve manifest")
                raise Exception("could not retrieve manifest")
            
        except Exception as err:
            raise err
    except Exception as err:
        raise err

    return(ret)

def get_image_manifest_skopeo(url, registry, repo, intag=None, indigest=None, topdigest=None, user=None, pw=None, verify=True, topmanifest=None):
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
        try:
            rawmanifest = get_image_manifest_skopeo_raw(pullstring, user=user, pw=pw, verify=verify)
            digest = manifest_to_digest(rawmanifest)
            manifest = json.loads(rawmanifest)
            if topmanifest is None:
                topmanifest = json.loads(rawmanifest)
            if not topdigest:
                topdigest = digest

            if manifest.get('schemaVersion') == 2 and manifest.get('mediaType') == 'application/vnd.docker.distribution.manifest.list.v2+json':
                # Get the arch-specific version for amd64 and linux
                new_digest = None
                for entry in manifest.get('manifests'):
                    platform = entry.get('platform')
                    if platform and platform.get('architecture') in ['amd64'] and platform.get('os') in ['linux', 'windows']:
                        new_digest = entry.get('digest')
                        break

                return get_image_manifest_skopeo(url=url, registry=registry, repo=repo, intag=None, indigest=new_digest, user=user, pw=pw, verify=verify, topdigest=topdigest, topmanifest=topmanifest)
        except Exception as err:
            logger.warn("CMD failed - exception: " + str(err))
            raise err

    except Exception as err:
        import traceback
        traceback.print_exc()
        raise err

    if not manifest or not digest:
        raise SkopeoError(msg="No digest/manifest from skopeo")

    return(manifest, digest, topdigest, topmanifest)

class SkopeoError(AnchoreException):

    def __init__(self, cmd=None, rc=None, err=None, out=None, msg='Error encountered in skopeo operation'):
        from anchore_engine.common.errors import AnchoreError

        self.cmd = ' '.join(cmd) if isinstance(cmd, list) else cmd
        self.exitcode = rc
        self.stderr = str(err).replace('\r', ' ').replace('\n', ' ').strip() if err else None
        self.stdout = str(out).replace('\r', ' ').replace('\n', ' ').strip() if out else None
        self.msg = msg
        try:
            if "unauthorized" in self.stderr:
                self.error_code = AnchoreError.REGISTRY_PERMISSION_DENIED.name
            elif "manifest unknown" in self.stderr:
                self.error_code = AnchoreError.REGISTRY_IMAGE_NOT_FOUND.name
            elif "connection refused" in self.stderr or "no route to host" in self.stderr:
                self.error_code = AnchoreError.REGISTRY_NOT_ACCESSIBLE.name
            elif "error pinging registry" in self.stderr:
                self.error_code = AnchoreError.REGISTRY_NOT_SUPPORTED.name
            elif "no image found in manifest list for architecture amd64, OS linux" in self.stderr:
                self.error_code = AnchoreError.OSARCH_MISMATCH.name
            else:
                self.error_code = AnchoreError.SKOPEO_UNKNOWN_ERROR.name
        except:
            self.error_code = AnchoreError.UNKNOWN.name
        

    def __repr__(self):
        return '{}. cmd={}, rc={}, stdout={}, stderr={}, error_code={}'.format(self.msg, self.cmd, self.exitcode, self.stdout, self.stderr, self.error_code)

    def __str__(self):
        return '{}. cmd={}, rc={}, stdout={}, stderr={}, error_code={}'.format(self.msg, self.cmd, self.exitcode, self.stdout, self.stderr, self.error_code)
