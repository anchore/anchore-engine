def init_analyzer_cmdline(argv, name):
    ret = {}

    if len(argv) < 4:
        print "ERROR: invalid input"
        raise Exception

    anchore_conf = AnchoreConfiguration()
    anchore_common_context_setup(anchore_conf)

    ret['analyzer_config'] = None
    anchore_analyzer_configfile = '/'.join([anchore_conf.config_dir, 'analyzer_config.yaml'])
    if os.path.exists(anchore_analyzer_configfile):
        try:
            with open(anchore_analyzer_configfile, 'r') as FH:
                anchore_analyzer_config = yaml.safe_load(FH.read())
        except Exception as err:
            print "ERROR: could not parse the analyzer_config.yaml - exception: " + str(err)
            raise err

        if anchore_analyzer_config and name in anchore_analyzer_config:
            ret['analyzer_config'] = anchore_analyzer_config[name]

    ret['anchore_config'] = anchore_conf.data

    ret['name'] = name

    FH=open(argv[0], 'r')
    ret['selfcsum'] = hashlib.md5(FH.read()).hexdigest()
    FH.close()
    ret['imgid'] = argv[1]

    try:
        fullid = discover_imageId(argv[1])
    except:
        fullid = None
    if fullid:
        ret['imgid_full'] = fullid
    else:
        ret['imgid_full'] = ret['imgid']

    ret['dirs'] = {}
    ret['dirs']['datadir'] = argv[2]
    ret['dirs']['outputdir'] = '/'.join([argv[3], "analyzer_output", name])
    ret['dirs']['unpackdir'] = argv[4]

    for d in ret['dirs'].keys():
        if not os.path.isdir(ret['dirs'][d]):
            try:
                os.makedirs(ret['dirs'][d])
            except Exception as err:
                print "ERROR: cannot find/create input dir '"+ret['dirs'][d]+"'"
                raise err

    return(ret)
