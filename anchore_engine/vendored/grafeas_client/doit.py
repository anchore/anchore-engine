#!/usr/bin/python

import client_python.v1alpha1.swagger_client
import json
import sys
import datetime

def make_vulnerability_detail(cveId, anch_cves):
    ret_details = []
    ret_urls = []
    links = []
    for v in anch_cves:
        if cveId == v['Vulnerability']['Name']:
            anch_cve = v['Vulnerability']

            distro, distrovers = anch_cve['NamespaceName'].split(":", 1)

            for fixedIn in anch_cve['FixedIn']:
                retel = {
                    'cpe_uri': None,
                    'package': None,
                    'severity_name': None,
                    'description': None,
                    'min_affected_version': None,
                    'max_affected_version': None,
                    'fixed_location': None
                }

                # TODO - assemble/fetch the right CPE
                retel['cpe_uri'] = "cpe:/o:"+distro+":"+distro+"_linux:"+distrovers
                retel['package'] = fixedIn['Name']
                retel['min_affected_version'] = 'MINIMUM'
                retel['severity_name'] = anch_cve['Severity'].upper()
                retel['description'] = anch_cve['Description']
                if fixedIn['Version'] != "None":
                    fix_version = client_python.v1alpha1.swagger_client.Version(kind="NORMAL", name=fixedIn['Version'])
                else:
                    fix_version = client_python.v1alpha1.swagger_client.Version(kind="MAXIMUM")

                retel['fixed_location'] = client_python.v1alpha1.swagger_client.VulnerabilityLocation(cpe_uri=retel['cpe_uri'], package=retel['package'], version=fix_version)

                detail = client_python.v1alpha1.swagger_client.Detail(**retel)
                ret_details.append(detail)
                if anch_cve['Link'] not in links:
                    links.append(anch_cve['Link'])

    for url in links:
        ret_urls.append(client_python.v1alpha1.swagger_client.RelatedUrl(url=url, label="More Info"))

    return(ret_details, ret_urls)

def get_cve_data(nvd_cve):
    ret = {
        'score': None,
        'severity': None
    }
    if 'vuln:cvss' in nvd_cve and 'cvss:base_metrics' in nvd_cve['vuln:cvss'] and "cvss:score" in nvd_cve['vuln:cvss']['cvss:base_metrics']:
        score = float(nvd_cve['vuln:cvss']['cvss:base_metrics']['cvss:score'])
        ret['score'] = score
        if score <= 3.9:
            sev = "Low"
        elif score <= 6.9:
            sev = "Medium"
        elif score <= 10.0:
            sev = "High"
        else:
            sev = "Unknown"
        ret['severity'] = sev.upper()

    return(ret)

with open("/tmp/mycve.json", 'r') as FH:
    cves = json.loads(FH.read())


feedfiles = ['/root/.anchore/feeds/vulnerabilities/alpine:3.3/data_1970-01-01_to_2017-10-17.json', '/root/.anchore/feeds/vulnerabilities/alpine:3.3/data_2017-10-17_to_2017-10-18.json', '/root/.anchore/feeds/vulnerabilities/alpine:3.3/data_2017-10-18_to_2017-10-18.json', '/root/.anchore/feeds/vulnerabilities/alpine:3.4/data_1970-01-01_to_2017-10-17.json', '/root/.anchore/feeds/vulnerabilities/alpine:3.4/data_2017-10-17_to_2017-10-18.json', '/root/.anchore/feeds/vulnerabilities/alpine:3.4/data_2017-10-18_to_2017-10-18.json', '/root/.anchore/feeds/vulnerabilities/alpine:3.5/data_1970-01-01_to_2017-10-17.json', '/root/.anchore/feeds/vulnerabilities/alpine:3.5/data_2017-10-17_to_2017-10-18.json', '/root/.anchore/feeds/vulnerabilities/alpine:3.5/data_2017-10-18_to_2017-10-18.json', '/root/.anchore/feeds/vulnerabilities/alpine:3.6/data_1970-01-01_to_2017-10-17.json', '/root/.anchore/feeds/vulnerabilities/alpine:3.6/data_2017-10-17_to_2017-10-18.json', '/root/.anchore/feeds/vulnerabilities/alpine:3.6/data_2017-10-18_to_2017-10-18.json', '/root/.anchore/feeds/vulnerabilities/centos:5/data_1970-01-01_to_2017-10-17.json', '/root/.anchore/feeds/vulnerabilities/centos:5/data_2017-10-17_to_2017-10-18.json', '/root/.anchore/feeds/vulnerabilities/centos:5/data_2017-10-18_to_2017-10-18.json', '/root/.anchore/feeds/vulnerabilities/centos:6/data_1970-01-01_to_2017-10-17.json', '/root/.anchore/feeds/vulnerabilities/centos:6/data_2017-10-17_to_2017-10-18.json', '/root/.anchore/feeds/vulnerabilities/centos:6/data_2017-10-18_to_2017-10-18.json', '/root/.anchore/feeds/vulnerabilities/centos:7/data_1970-01-01_to_2017-10-17.json', '/root/.anchore/feeds/vulnerabilities/centos:7/data_2017-10-17_to_2017-10-18.json', '/root/.anchore/feeds/vulnerabilities/centos:7/data_2017-10-18_to_2017-10-18.json', '/root/.anchore/feeds/vulnerabilities/debian:7/data_1970-01-01_to_2017-10-17.json', '/root/.anchore/feeds/vulnerabilities/debian:7/data_2017-10-17_to_2017-10-18.json', '/root/.anchore/feeds/vulnerabilities/debian:7/data_2017-10-18_to_2017-10-18.json', '/root/.anchore/feeds/vulnerabilities/debian:8/data_1970-01-01_to_2017-10-17.json', '/root/.anchore/feeds/vulnerabilities/debian:8/data_2017-10-17_to_2017-10-18.json', '/root/.anchore/feeds/vulnerabilities/debian:8/data_2017-10-18_to_2017-10-18.json', '/root/.anchore/feeds/vulnerabilities/debian:9/data_1970-01-01_to_2017-10-17.json', '/root/.anchore/feeds/vulnerabilities/debian:9/data_2017-10-17_to_2017-10-18.json', '/root/.anchore/feeds/vulnerabilities/debian:9/data_2017-10-18_to_2017-10-18.json', '/root/.anchore/feeds/vulnerabilities/debian:unstable/data_1970-01-01_to_2017-10-17.json', '/root/.anchore/feeds/vulnerabilities/debian:unstable/data_2017-10-17_to_2017-10-18.json', '/root/.anchore/feeds/vulnerabilities/debian:unstable/data_2017-10-18_to_2017-10-18.json', '/root/.anchore/feeds/vulnerabilities/ol:5/data_1970-01-01_to_2017-10-17.json', '/root/.anchore/feeds/vulnerabilities/ol:5/data_2017-10-17_to_2017-10-18.json', '/root/.anchore/feeds/vulnerabilities/ol:5/data_2017-10-18_to_2017-10-18.json', '/root/.anchore/feeds/vulnerabilities/ol:6/data_1970-01-01_to_2017-10-17.json', '/root/.anchore/feeds/vulnerabilities/ol:6/data_2017-10-17_to_2017-10-18.json', '/root/.anchore/feeds/vulnerabilities/ol:6/data_2017-10-18_to_2017-10-18.json', '/root/.anchore/feeds/vulnerabilities/ol:7/data_1970-01-01_to_2017-10-17.json', '/root/.anchore/feeds/vulnerabilities/ol:7/data_2017-10-17_to_2017-10-18.json', '/root/.anchore/feeds/vulnerabilities/ol:7/data_2017-10-18_to_2017-10-18.json', '/root/.anchore/feeds/vulnerabilities/ubuntu:12.04/data_1970-01-01_to_2017-10-17.json', '/root/.anchore/feeds/vulnerabilities/ubuntu:12.04/data_2017-10-17_to_2017-10-18.json', '/root/.anchore/feeds/vulnerabilities/ubuntu:12.04/data_2017-10-18_to_2017-10-18.json', '/root/.anchore/feeds/vulnerabilities/ubuntu:12.10/data_1970-01-01_to_2017-10-17.json', '/root/.anchore/feeds/vulnerabilities/ubuntu:12.10/data_2017-10-17_to_2017-10-18.json', '/root/.anchore/feeds/vulnerabilities/ubuntu:12.10/data_2017-10-18_to_2017-10-18.json', '/root/.anchore/feeds/vulnerabilities/ubuntu:13.04/data_1970-01-01_to_2017-10-17.json', '/root/.anchore/feeds/vulnerabilities/ubuntu:13.04/data_2017-10-17_to_2017-10-18.json', '/root/.anchore/feeds/vulnerabilities/ubuntu:13.04/data_2017-10-18_to_2017-10-18.json', '/root/.anchore/feeds/vulnerabilities/ubuntu:14.04/data_1970-01-01_to_2017-10-17.json', '/root/.anchore/feeds/vulnerabilities/ubuntu:14.04/data_2017-10-17_to_2017-10-18.json', '/root/.anchore/feeds/vulnerabilities/ubuntu:14.04/data_2017-10-18_to_2017-10-18.json', '/root/.anchore/feeds/vulnerabilities/ubuntu:14.10/data_1970-01-01_to_2017-10-17.json', '/root/.anchore/feeds/vulnerabilities/ubuntu:14.10/data_2017-10-17_to_2017-10-18.json', '/root/.anchore/feeds/vulnerabilities/ubuntu:14.10/data_2017-10-18_to_2017-10-18.json', '/root/.anchore/feeds/vulnerabilities/ubuntu:15.04/data_1970-01-01_to_2017-10-17.json', '/root/.anchore/feeds/vulnerabilities/ubuntu:15.04/data_2017-10-17_to_2017-10-18.json', '/root/.anchore/feeds/vulnerabilities/ubuntu:15.04/data_2017-10-18_to_2017-10-18.json', '/root/.anchore/feeds/vulnerabilities/ubuntu:15.10/data_1970-01-01_to_2017-10-17.json', '/root/.anchore/feeds/vulnerabilities/ubuntu:15.10/data_2017-10-17_to_2017-10-18.json', '/root/.anchore/feeds/vulnerabilities/ubuntu:15.10/data_2017-10-18_to_2017-10-18.json', '/root/.anchore/feeds/vulnerabilities/ubuntu:16.04/data_1970-01-01_to_2017-10-17.json', '/root/.anchore/feeds/vulnerabilities/ubuntu:16.04/data_2017-10-17_to_2017-10-18.json', '/root/.anchore/feeds/vulnerabilities/ubuntu:16.04/data_2017-10-18_to_2017-10-18.json', '/root/.anchore/feeds/vulnerabilities/ubuntu:16.10/data_1970-01-01_to_2017-10-17.json', '/root/.anchore/feeds/vulnerabilities/ubuntu:16.10/data_2017-10-17_to_2017-10-18.json', '/root/.anchore/feeds/vulnerabilities/ubuntu:16.10/data_2017-10-18_to_2017-10-18.json', '/root/.anchore/feeds/vulnerabilities/ubuntu:17.04/data_1970-01-01_to_2017-10-17.json', '/root/.anchore/feeds/vulnerabilities/ubuntu:17.04/data_2017-10-17_to_2017-10-18.json', '/root/.anchore/feeds/vulnerabilities/ubuntu:17.04/data_2017-10-18_to_2017-10-18.json']

anchcves = []
for f in feedfiles:
    with open(f, 'r') as FH:
        anchcves = anchcves + json.loads(FH.read())

cveId = cves.keys()[0]

mycve = cves[cveId]

cve_data = get_cve_data(mycve)
nistInfo = "N/A"
cvss_score = cve_data['score']
severity = cve_data['severity']

vulnerability_details, external_urls = make_vulnerability_detail(cveId, anchcves)

package_type = "native"
#help(client_python.v1alpha1.swagger_client.VulnerabilityType())
vulnerability_type = client_python.v1alpha1.swagger_client.VulnerabilityType(
    cvss_score=cvss_score,
    severity=severity,
    details=vulnerability_details,
    package_type=package_type
)

newnote = client_python.v1alpha1.swagger_client.Note(
    name="projects/security-scanner/notes/"+cveId, 
    short_description=cveId,
    long_description="NIST vectors: " + nistInfo,
    related_url=external_urls,
    kind="PACKAGE_VULNERABILITY",
    create_time=str(datetime.datetime.utcnow()),
    update_time=str(datetime.datetime.utcnow()),
    vulnerability_type=vulnerability_type
)

#help (emptynote)

d = newnote.to_dict()
print json.dumps(d, indent=4)


#help (client_python.v1alpha1.swagger_client.GrafeasApi)
api_client = client_python.v1alpha1.swagger_client.api_client.ApiClient(host="localhost:8080")
api_instance = client_python.v1alpha1.swagger_client.GrafeasApi(api_client=api_client)
projects_id = "security-scanner"
note_id = cveId
note = newnote

print "ADD RESPONSE\n------------"
try:
    api_response = api_instance.create_note(projects_id, note_id=note_id, note=note)
    print api_response
except Exception as err:
    print err

print "GET RESPONSE\n------------"
try:
    api_response = api_instance.get_note(projects_id, note_id)
    print api_response
except Exception as err:
    print err

