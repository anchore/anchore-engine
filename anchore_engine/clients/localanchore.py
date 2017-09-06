import filecmp
import json
import os
import re
import shutil
import subprocess
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
                    logger.debug("checking default yaml")
                    # check that it is at least valid yaml before copying in place
                    with open(default_file, 'r') as FH:
                        yaml.safe_load(FH)

                    logger.info("copying new config into place: " + str(src) + " -> " + str(dst))
                    shutil.copy(default_file, installed_file)

    except Exception as err:
        logger.warn("could not check/install analyzer anchore_engine.configuration - exception: " + str(err))

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
            try:
                sout = subprocess.check_output(cmd)
            except subprocess.CalledProcessError as err:
                if (err.returncode == 1 or err.returncode == 2) and err.output:
                    sout = err.output.decode('utf8')
                else:
                    sout = "invalid query"
            except Exception as err:
                raise err
        except Exception as err:
            logger.warn("image removal from anchore failed - exception: " + str(err))

    logger.debug("image removed: " + str(pullstring))
    return(True)

def run_query(pullstring, query):
    ret = {}
    
    query_name = query['name']
    
    params = []
    for p in query['params']:
        param = p['key']
        if 'val' in p and p['val']:
            param = param + "=" + p['val']
        params.append(param)
    
    cmd = ['anchore', '--json', 'query', '--image', pullstring, query_name] + params
    try:
        logger.debug("running query: " + str(' '.join(cmd)))
        try:
            sout = subprocess.check_output(cmd)
        except subprocess.CalledProcessError as err:
            if (err.returncode == 1 or err.returncode == 2) and err.output:
                sout = err.output.decode('utf8')
            else:
                sout = "invalid query"
        except Exception as err:
            raise err

        try:
            query_result = json.loads(sout)
        except Exception as err:
            query_result = {'error':str(sout)}

        ret = query_result

    except Exception as err:
        raise err
        
    return(ret)

def run_queries(pullstring, image_detail, args={}):
    ret = {}

    queries_to_run = [
        {'name':'list-package-detail', 'params':[ {'key':'all'} ] },
        {'name':'list-files-detail', 'params':[ {'key':'all'} ] },
        {'name':'list-npm-detail', 'params':[ {'key':'all'} ] },
        {'name':'list-gem-detail', 'params':[ {'key':'all'} ] }
        #{'name':'cve-scan', 'params':[ {'key':'all'} ] }
    ]

    for query in queries_to_run:
        try:
            query_name = query['name']
            ret[query_name] = {}
            query_data = run_query(pullstring, query)
            if query_data:
                ret[query_name] = query_data
        except Exception as err:
            logger.warn("query failed: " + str(query) + " - exception: " + str(err))

    return(ret)

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
            sout = subprocess.check_output(cmd)
            try:
                ret = True
            except Exception as err:
                raise(err)
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

def do_image_import(pullstring, image_detail, image_content, args={}):
    ret = False

    localconfig = anchore_engine.configuration.localconfig.get_config()

    thefile = None
    try:

        #import random
        #thefile = os.path.join(localconfig['tmp_dir'], "tmp"+str(random.randint(0, 999999999999)))
        #icbuf = json.dumps(image_content)
        #with open(thefile, 'w') as OFH:
        #    OFH.write(icbuf)

        with tempfile.NamedTemporaryFile(dir=localconfig['tmp_dir'], delete=False) as OFH:
            thefile = OFH.name
            OFH.write(json.dumps(image_content))

        cmd = ['anchore', 'toolbox', 'import', '--infile', thefile, '--force']
        for a in args:
            cmd.append(a)
            cmd.append(args[a])

        try:
            logger.debug("running command: " + str(' '.join(cmd)))

            sout = subprocess.check_output(cmd)
            try:
                ret = True
            except Exception as err:
                raise(err)
        except Exception as err:
            raise err
    except Exception as err:
        logger.error(str(err))
    finally:
        if thefile and os.path.exists(thefile):
            os.remove(thefile)

    return(ret)

def get_image_export(pullstring, image_detail, args={}):
    ret = {}

    if True:
        cmd = ['anchore', 'toolbox', '--image', pullstring, 'export', '--outfile', '-']
        for a in args:
            cmd.append(a)
            cmd.append(args[a])

        try:
            sout = subprocess.check_output(cmd)
            try:
                ret = json.loads(sout)
            except Exception as err:
                raise(err)
        except Exception as err:
            logger.error(str(err))

    return(ret)

def feedsync(feed=None, args={}, anchore_user=None, anchore_pw=None):
    ret = {}

    if True:
        try:
            try:
                anchore_login(anchore_user, anchore_pw)
            except Exception as err:
                logger.warn("could not log in, will try sync as anon - exception: " + str(err))
                anchore_logout()

            if feed:
                cmd = ['anchore', '--json', 'feeds', 'sub', feed]
                try:
                    logger.debug("running feed subscriber: " + str(' '.join(cmd)))
                    sout = subprocess.check_output(cmd)
                except Exception as err:
                    raise err


            cmd = ['anchore', '--json', 'feeds', 'sync', '--do-compact']
            for a in args:
                cmd.append(a)
                cmd.append(args[a])

            logger.debug("running feed syncer: " + str(' '.join(cmd)))
            sout = subprocess.check_output(cmd)

            cmd = ['anchore', '--json', 'feeds', 'list', '--showgroups']
            logger.debug("running feed lister: " + str(' '.join(cmd)))
            sout = subprocess.check_output(cmd)
            try:
                ret = json.loads(sout)
            except Exception as err:
                raise(err)

        except Exception as err:
            logger.error(str(err))
        finally:
            #anchore_logout()
            pass

    return(ret)

def anchore_login(anchore_user, anchore_pw):
    try:
        cmd = ['anchore', '--json', 'whoami']
        logger.debug("running anchore whoami check")
        
        sout = None
        current_loggedin_user = None
        try:
            sout = subprocess.check_output(cmd)
            logger.debug("whoami output: " + str(sout))
            whoami_output = json.loads(sout)
            if whoami_output and 'Current user' in whoami_output:
                current_loggedin_user = whoami_output['Current user']
        except subprocess.CalledProcessError as err:
            logger.warn("whoami failed: " + str(err))
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

        #try:
        #    anchore_logout()
        #except:
        #    pass

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
        try:
            sout = subprocess.check_output(cmd)
            logger.debug("login output: " + str(sout))
        except subprocess.CalledProcessError as err:
            logger.debug("login failed: " + str(err))
            raise Exception("login failed: " + str(err.output))
        except Exception as err:
            logger.debug("login failed: " + str(err))
            raise err    
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
        subprocess.check_output(['anchore', 'logout'])
    except Exception as err:
        logger.error("logout failed: " + str(err))
        raise err

def get_bundle(anchore_user, anchore_pw):
    ret = {}

    try:
        anchore_login(anchore_user, anchore_pw)
        
        cmd = ['anchore', '--json', 'policybundle', 'sync', '--outfile', '-']
        logger.debug("running bundle syncer: " + str(' '.join(cmd)))
        sout = None
        try:
            sout = subprocess.check_output(cmd)
            ret = json.loads(sout)
        except subprocess.CalledProcessError as err:
            logger.debug("sync failed: " + str(err.output))
            raise err
        except Exception as err:
            logger.debug("sync failed: " + str(err))
            raise err
        finally:
            #anchore_logout()
            #subprocess.check_output(['anchore', 'logout'])
            pass

    except Exception as err:
        logger.debug("operation failed: " + str(err))
        raise err
    finally:
        #subprocess.check_output(['anchore', 'logout'])
        #os.environ['ANCHOREUSER'] = ""
        #os.environ['ANCHOREPASS'] = ""
        pass

    return(ret)

def eval_bundle(pullstring, tag, image_detail, bundleId, bundle_content, args={}):
    ret = False

    localconfig = anchore_engine.configuration.localconfig.get_config()

    thefile = None
    try:
        usetag = tag

        bcbuf = json.dumps(bundle_content)
        with tempfile.NamedTemporaryFile(dir=localconfig['tmp_dir'], delete=False) as OFH:
            thefile = OFH.name
            OFH.write(bcbuf)

        cmd = ['anchore', '--json', 'gate', '--image', pullstring, '--run-bundle', '--bundlefile', thefile, '--usetag', usetag]
        for a in args:
            cmd.append(a)
            cmd.append(args[a])

        try:
            logger.debug("running policy evaluator: " + str(' '.join(cmd)))
            try:
                sout = subprocess.check_output(cmd)
                ret = json.loads(sout)
            except subprocess.CalledProcessError as err:
                if (err.returncode == 1 or err.returncode == 2) and err.output:
                    sout = err.output.decode('utf8')
                    ret = json.loads(sout)
                else:
                    logger.warn("uncaught exit code from cmd, or output is empty: " + str(err.returncode) + " : " + str(err.output))

            except Exception as err:
                raise(err)
        except Exception as err:
            logger.error(str(err))
    except Exception as err:
        raise err
    finally:
        if thefile and os.path.exists(thefile):
            os.remove(thefile)

    return(ret)

def get_config():
    ret = {}
    logger.debug("fetching local anchore anchore_engine.configuration")
    if True:
        cmd = ['anchore', '--json', 'system', 'status', '--conf']
        try:
            sout = subprocess.check_output(cmd)
            try:
                ret = json.loads(sout)
            except Exception as err:
                raise(err)
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

