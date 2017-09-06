import json

import requests

#s = requests.session()
#s.config['keep_alive'] = False

def get(url, **kwargs):
    return(get_req(url, **kwargs))

def post(url, **kwargs):
    return(post_req(url, **kwargs))

def put(url, **kwargs):
    return(put_req(url, **kwargs))

def delete(url, **kwargs):
    return(delete_req(url, **kwargs))

def get_req(url, **kwargs):
    return(requests.get(url, **kwargs))

def post_req(url, **kwargs):
    return(requests.post(url, **kwargs))

def put_req(url, **kwargs):
    return(requests.put(url, **kwargs))

def delete_req(url, **kwargs):
    return(requests.delete(url, **kwargs))

def fpost(url, **kwargs):
    httpcode = 500
    rawdata = ""
    jsondata = {}
    try:
        r = requests.post(url, stream=True, **kwargs)
        httpcode = r.status_code
        rawdata = ""
        for rchunk in r.iter_content(8192*100):
            rawdata = rawdata + rchunk
        #rawdata = r.text
        try:
            jsondata = json.loads(rawdata)
        except:
            jsondata = {}
    except Exception as err:
        rawdata = str(err)
    return(httpcode, jsondata, rawdata)

def fput(url, **kwargs):
    httpcode = 500
    rawdata = ""
    jsondata = {}
    try:
        r = requests.put(url, stream=True, **kwargs)
        httpcode = r.status_code
        rawdata = ""
        for rchunk in r.iter_content(8192*100):
            rawdata = rawdata + rchunk
        #rawdata = r.text
        try:
            jsondata = json.loads(rawdata)
        except:
            jsondata = {}
    except Exception as err:
        rawdata = str(err)
    return(httpcode, jsondata, rawdata)

def fget(url, **kwargs):
    httpcode = 500
    rawdata = ""
    jsondata = {}
    try:
        r = requests.get(url, stream=True, **kwargs)
        httpcode = r.status_code
        rawdata = ""
        for rchunk in r.iter_content(8192*100):
            rawdata = rawdata + rchunk
        #rawdata = r.text
        try:
            jsondata = json.loads(rawdata)
        except:
            jsondata = {}
    except Exception as err:
        rawdata = str(err)

    return(httpcode, jsondata, rawdata)

def fdelete(url, **kwargs):
    httpcode = 500
    rawdata = ""
    jsondata = {}
    try:
        r = requests.delete(url, stream=True, **kwargs)
        httpcode = r.status_code
        rawdata = ""
        for rchunk in r.iter_content(8192*100):
            rawdata = rawdata + rchunk
        #rawdata = r.text
        try:
            jsondata = json.loads(rawdata)
        except:
            jsondata = {}
    except Exception as err:
        rawdata = str(err)
    return(httpcode, jsondata, rawdata)

def anchy_get(url, raw=False, **kwargs):
    ret = True

    (httpcode, jsondata, rawdata) = fget(url, **kwargs)
    if httpcode == 200:
        if raw:
            ret = rawdata
        else:
            if jsondata != None:
                ret = jsondata
            elif rawdata:
                ret = rawdata
            else:
                ret = True
    else:
        e = Exception("failed get url="+str(url))
        e.__dict__.update({'httpcode':httpcode, 'anchore_error_raw':str(rawdata), 'anchore_error_json':jsondata})
        raise e

    return(ret)

def anchy_post(url, raw=False, **kwargs):
    ret = True

    (httpcode, jsondata, rawdata) = fpost(url, **kwargs)
    if httpcode == 200:
        if raw:
            ret = rawdata
        else:
            if jsondata != None:
                ret = jsondata
            elif rawdata:
                ret = rawdata
            else:
                ret = True
    else:
        e = Exception("failed post url="+str(url))
        e.__dict__.update({'httpcode':httpcode, 'anchore_error_raw':str(rawdata), 'anchore_error_json':jsondata})
        raise e

    return(ret)


def anchy_put(url, raw=False, **kwargs):
    ret = True

    (httpcode, jsondata, rawdata) = fput(url, **kwargs)
    if httpcode == 200:
        if raw:
            ret = rawdata
        else:
            if jsondata != None:
                ret = jsondata
            elif rawdata:
                ret = rawdata
            else:
                ret = True
    else:
        e = Exception("failed put url="+str(url))
        e.__dict__.update({'httpcode':httpcode, 'anchore_error_raw':str(rawdata), 'anchore_error_json':jsondata})
        raise e

    return(ret)


def anchy_delete(url, raw=False, **kwargs):
    ret = True

    (httpcode, jsondata, rawdata) = fdelete(url, **kwargs)
    if httpcode == 200:
        if raw:
            ret = rawdata
        else:
            if jsondata != None:
                ret = jsondata
            elif rawdata:
                ret = rawdata
            else:
                ret = True
    else:
        e = Exception("failed delete url="+str(url))
        e.__dict__.update({'httpcode':httpcode, 'anchore_error_raw':str(rawdata), 'anchore_error_json':jsondata})
        raise e

    return(ret)
