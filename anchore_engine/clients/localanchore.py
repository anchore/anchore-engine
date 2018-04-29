import filecmp
import json
import os
import re
import shutil
import tempfile
import threading

import yaml

import anchore_engine.auth.docker_registry
import anchore_engine.configuration.localconfig
from anchore_engine.subsys import logger

anchorelock = threading.Lock()
anchorelocks = {}

def get_anchorelock(lockId=None):
    global anchorelock, anchorelocks
    ret = anchorelock

    # first, check if we need to update the anchore configs
    localconfig = anchore_engine.configuration.localconfig.get_config()
    if 'anchore_scanner_config' not in localconfig:
        localconfig['anchore_scanner_config'] = get_config()
        anchore_config = localconfig['anchore_scanner_config']
    anchore_config = localconfig['anchore_scanner_config']

    try:
        for src,dst in [(localconfig['anchore_scanner_analyzer_config_file'], os.path.join(anchore_config['anchore_data_dir'], 'conf', 'analyzer_config.yaml')), (os.path.join(localconfig['service_dir'], 'anchore_config.yaml'), os.path.join(anchore_config['anchore_data_dir'], 'conf', 'config.yaml'))]:
            logger.debug("checking defaults against installed: " + src + " : " + dst)
            if os.path.exists(src) and os.path.exists(dst):
                default_file = src
                installed_file = dst
                if not filecmp.cmp(default_file, installed_file):
                    logger.debug("checking source yaml ("+str(default_file)+")")
                    # check that it is at least valid yaml before copying in place
                    with open(default_file, 'r') as FH:
                        yaml.safe_load(FH)

                    logger.info("copying new config into place: " + str(src) + " -> " + str(dst))
                    shutil.copy(default_file, installed_file)

    except Exception as err:
        logger.warn("could not check/install analyzer anchore configurations (please check yaml format of your configuration files), continuing with default - exception: " + str(err))

    if lockId:
        lockId = lockId.encode('base64')
        if lockId not in anchorelocks:
            anchorelocks[lockId] = threading.Lock()
        ret = anchorelocks[lockId]
        logger.spew("all locks: " + str(anchorelocks))
    else:
        ret = anchorelock

    return(ret)

def pull(userId, pullstring, image_detail, args={}, pulltags=False, registry_creds=[]):
    ret = False

    if True:
        registry = image_detail['registry']
        
        cli = anchore_engine.auth.docker_registry.get_authenticated_cli(userId, registry, registry_creds=registry_creds)

        if True:
            try:
                docker_data = {}
                try:
                    docker_data = cli.inspect_image(pullstring)
                except:
                    pass

                if not docker_data:
                    logger.debug("pulling image: " + str(pullstring))
                    a = cli.pull(pullstring)
                    docker_data = cli.inspect_image(pullstring)

                if pulltags:
                    fulltag = image_detail['registry'] + "/" + image_detail['repo'] + ":" + image_detail['tag']
                    if fulltag not in docker_data['RepoTags']:
                        logger.debug("pulling tag: "  +str(fulltag))
                        a = cli.pull(fulltag)

                ret = True
            except Exception as err:
                raise Exception("cannot pull image: " + str(image_detail) + " - exception: " + str(err))
        else:
            ret = True

    if ret:
        image_data = cli.inspect_image(pullstring)
        ret = image_data

    return(ret)

def remove_image(pullstring, docker_remove=True, anchore_remove=True):
    ret = False

    if docker_remove:
        cli = anchore_engine.auth.docker_registry.get_authenticated_cli(None, None)
        try:
            cli.remove_image(pullstring, force=True)
        except Exception as err:
            logger.warn("image removal from docker host failed - exception: " + str(err))

    if anchore_remove:
        cmd = ['anchore', 'toolbox', '--image', pullstring, 'delete', '--dontask']
        try:
            logger.debug("removing image from anchore: " + str(' '.join(cmd)))
            rc, sout, serr = anchore_engine.utils.run_command_list(cmd)
        except Exception as err:
            logger.warn("image removal from anchore failed - exception: " + str(err))

    logger.debug("image removed: " + str(pullstring))
    return(True)

def analyze(pullstring, image_detail, args={}):
    ret = False
    localconfig = anchore_engine.configuration.localconfig.get_config()

    dockerfile = None

    try:
        try:
            if 'dockerfile' in image_detail and image_detail['dockerfile']:
                ddata = image_detail['dockerfile'].decode('base64')
                with tempfile.NamedTemporaryFile(dir=localconfig['tmp_dir'], delete=False) as OFH:
                    #OFH.write(json.dumps(ddata))
                    OFH.write(ddata)
                    dockerfile = OFH.name
                #with open(dockerfile, 'r') as FH:
                #    logger.debug("HERRO: " + str(FH.read()))

        except Exception as err:
            logger.error("dockerfile decode/file write error: " + str(err))
            raise(err)

        cmd = ['anchore', 'analyze', '--image', pullstring]
        for a in args:
            cmd.append(a)
            cmd.append(args[a])
        if dockerfile:
            cmd = cmd + ['--dockerfile', dockerfile]

        try:
            logger.debug("running analyzer: " + str(' '.join(cmd)))
            rc, sout, serr = anchore_engine.utils.run_command_list(cmd)
            ret = True
        except Exception as err:
            raise err
    except Exception as err:
        logger.error(str(err))
    finally:
        try:
            if dockerfile and os.path.exists(dockerfile):
                os.remove(dockerfile)
        except Exception as err:
            logger.error("failed to remove temporary dockerfile: " + str(dockerfile))

    return(ret)

def get_image_export(pullstring, image_detail, args={}):
    ret = {}

    if True:
        cmd = ['anchore', 'toolbox', '--image', pullstring, 'export', '--outfile', '-']
        for a in args:
            cmd.append(a)
            cmd.append(args[a])

        try:
            rc, sout, serr = anchore_engine.utils.run_command_list(cmd)
            ret = json.loads(sout)
        except Exception as err:
            logger.error(str(err))

    return(ret)


def anchore_login(anchore_user, anchore_pw):
    try:
        cmd = ['anchore', '--json', 'whoami']
        logger.debug("running anchore whoami check")
        
        sout = None
        current_loggedin_user = None
        try:
            rc, sout, serr = anchore_engine.utils.run_command_list(cmd)
            logger.debug("whoami output: " + str(sout))
            whoami_output = json.loads(sout)
            if whoami_output and 'Current user' in whoami_output:
                current_loggedin_user = whoami_output['Current user']
        except Exception as err:
            logger.warn("whoami failed: " + str(err))

        if current_loggedin_user:
            skiplogin = False
            if current_loggedin_user == anchore_user:
                skiplogin = True
            elif "_id" in current_loggedin_user and current_loggedin_user['_id'] == anchore_user:
                skiplogin = True

            if skiplogin:
                logger.debug("already logged in as user ("+str(anchore_user)+"), skipping login")
                return(True)

        if anchore_user:
            os.environ['ANCHOREUSER'] = anchore_user
        else:
            try:
                del os.environ['ANCHOREUSER']
            except:
                pass

        if anchore_pw:
            os.environ['ANCHOREPASS'] = anchore_pw
        else:
            try:
                del os.environ['ANCHOREPASS']
            except:
                pass

        logger.spew("logging into anchore.io as user: " + str(anchore_user) + " : "  + str(anchore_pw))
        logger.debug("logging into anchore.io as user: " + str(anchore_user))

        cmd = ['anchore', 'login']
        logger.debug("running login: " + str(' '.join(cmd)))
        sout = None
        rc, sout, serr = anchore_engine.utils.run_command_list(cmd, env=os.environ)
        if rc:
            raise Exception("login command failed: sout={} serr={}".format(sout, serr))
    except Exception as err:
        logger.error("anchore login failed ("+str(anchore_user)+") - exception: " + str(err))
        raise err
    finally:
        try:
            del os.environ['ANCHOREUSER']
            del os.environ['ANCHOREPASS']
        except:
            pass

def anchore_logout():
    try:
        cmd = ['anchore', 'logout']
        rc, sout, serr = anchore_engine.utils.run_command_list(cmd)
    except Exception as err:
        logger.error("logout failed: " + str(err))
        raise err

def get_bundle(anchore_user, anchore_pw):
    ret = {}

    try:
        anchore_login(anchore_user, anchore_pw)
        
        cmd = ['anchore', '--json', 'policybundle', 'sync', '--outfile', '-']
        logger.debug("running bundle syncer: " + str(' '.join(cmd)))
        rc, sout, serr = anchore_engine.utils.run_command_list(cmd)
        ret = json.loads(sout)

    except Exception as err:
        logger.error("operation failed: " + str(err))
        raise err
    finally:
        pass

    return(ret)

def get_config():
    ret = {}
    logger.debug("fetching local anchore anchore_engine.configuration")
    if True:
        cmd = ['anchore', '--json', 'system', 'status', '--conf']
        try:
            rc, sout, serr = anchore_engine.utils.run_command_list(cmd)
            ret = json.loads(sout)
        except Exception as err:
            logger.error(str(err))

    return(ret)    

def parse_dockerimage_string(instr):
    host = None
    port = None
    repo = None
    tag = None
    registry = None
    repotag = None
    fulltag = None
    fulldigest = None
    digest = None
    imageId = None

    logger.debug("input string to parse: {}".format(instr))
    instr = instr.strip()
    if re.match(r".*[^a-zA-Z0-9@:/_\.\-]", instr):
        raise Exception("bad character in dockerimage string input ({})".format(instr))

    if re.match("^sha256:.*", instr):
        registry = 'docker.io'
        digest = instr

    elif len(instr) == 64 and not re.findall("[^0-9a-fA-F]+",instr):
        imageId = instr
    else:

        # get the host/port
        patt = re.match("(.*?)/(.*)", instr)
        if patt:
            a = patt.group(1)
            remain = patt.group(2)
            patt = re.match("(.*?):(.*)", a)
            if patt:
                host = patt.group(1)
                port = patt.group(2)
            elif a == 'docker.io':
                host = 'docker.io'
                port = None
            elif a in ['localhost', 'localhost.localdomain', 'localbuild']:
                host = a
                port = None
            else:
                patt = re.match(".*\..*", a)
                if patt:
                    host = a
                else:
                    host = 'docker.io'
                    remain = instr
                port = None

        else:
            host = 'docker.io'
            port = None
            remain = instr

        # get the repo/tag
        patt = re.match("(.*)@(.*)", remain)
        if patt:
            repo = patt.group(1)
            digest = patt.group(2)        
        else:
            patt = re.match("(.*):(.*)", remain)
            if patt:
                repo = patt.group(1)
                tag = patt.group(2)
            else:
                repo = remain
                tag = "latest"

        if not tag:
            tag = "latest"

        if port:
            registry = ':'.join([host, port])
        else:
            registry = host

        if digest:
            repotag = '@'.join([repo, digest])
        else:
            repotag = ':'.join([repo, tag])

        fulltag = '/'.join([registry, repotag])

        if not digest:
            digest = None
        else:
            fulldigest = registry + '/' + repo + '@' + digest
            tag = None
            fulltag = None
            repotag = None

    ret = {}
    ret['host'] = host
    ret['port'] = port
    ret['repo'] = repo
    ret['tag'] = tag
    ret['registry'] = registry
    ret['repotag'] = repotag
    ret['fulltag'] = fulltag
    ret['digest'] = digest
    ret['fulldigest'] = fulldigest
    ret['imageId'] = imageId

    if ret['fulldigest']:
        ret['pullstring'] = ret['fulldigest']
    elif ret['fulltag']:
        ret['pullstring'] = ret['fulltag']
    else:
        ret['pullstring'] = None

    return(ret)

