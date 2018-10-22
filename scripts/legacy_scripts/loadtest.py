#!/usr/bin/python

import json
import requests
import time

from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


def count_http_get(url):
    global count
    print(url)
    r = requests.get(url, auth=('admin', 'foobar'), verify=False)
    count = count + 1
    return(r)


timer_start = time.time()
count=0
while(True):
    base_url = "https://localhost:80/v1"

    url = '/'.join([base_url, 'images'])
    r = count_http_get(url)
    images = json.loads(r.text)
    #print "NUMIMAGES: " + str(len(images.keys()))
    for image in images:
        imageDigest = image['imageDigest']
        url = '/'.join([base_url, 'images', imageDigest])
        r = count_http_get(url)

        url = '/'.join([base_url, 'images', imageDigest, "check"])
        r = count_http_get(url)

        #image = json.loads(r.text)[imageDigest]
        #for image_detail in image['image_detail']:
        #    print "IMAGE: " + image['imageDigest'] + " : " + image_detail['registry'] + "/" + image_detail['repo'] + ":" + image_detail['tag']
        break

    url = '/'.join([base_url, 'policies'])
    r = count_http_get(url)
    policies = json.loads(r.text)
    for policy in policies:
        policyId = policy['policyId']
        url = '/'.join([base_url, 'policies', policyId])
        r = count_http_get(url)
       
    print("COUNT: " + str(count))
    if count > 1024:
        timer_stop = time.time()
        print("PROCESSED " + str(count) + " URLS IN " + str(timer_stop - timer_start) + " SECONDS: " + str(count / (timer_stop - timer_start)))
        exit(0)
