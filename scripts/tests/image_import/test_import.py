#!/usr/bin/env python3.8

"""
Simple example of an import flow of data output from `syft docker:nginx --output json` into Anchore. Uses syft v0.10.0 output.
"""

import base64
import json
import subprocess
import sys
import time

import requests

JSON_HEADER = {"Content-Type": "application/json"}
# endpoint = "http://localhost:8088"

# Defaults... don"t use these
AUTHC = ("admin", "foobar")

endpoint = sys.argv[1]

tag_to_scan = sys.argv[2]

# Always load from user input
dockerfile = sys.argv[3] if len(sys.argv) > 3 else None


def run_syft(image):
    output = subprocess.check_output(["syft", "docker:{}".format(image), "-o", "json"])
    return output


def check_response(api_resp: requests.Response) -> dict:
    print("Got response: {}".format(api_resp.status_code))
    print("Payload: {}".format(api_resp.json()))
    if api_resp.status_code != 200:
        sys.exit(1)

    resp_payload = api_resp.json()
    return resp_payload


def init_operation():
    print("Creating import operation")
    resp = requests.post(endpoint + "/imports/images", auth=AUTHC)

    # There are other fields present, such as "expires_at" timestamp, but all we need to proceed is the operation"s uuid.
    operation_id = check_response(resp).get("uuid")
    return operation_id


def load_syft_data(path):
    with open(path) as f:
        sbom_content = bytes(f.read(), "utf-8")

    print("Loaded content from file: {}".format(path))
    return sbom_content


def extract_syft_metadata(data):
    """
    Parse metadata from the syft output string

    :param data:
    :return:
    """
    # Parse into json to extract some info
    parsed = json.loads(str(data, "utf-8"))
    digest = parsed["source"]["target"][
        "manifestDigest"
    ]  # This is the image id, use it as digest since syft doesn't get a digest from a registry

    local_image_id = parsed["source"]["target"]["imageID"]
    tags = parsed["source"]["target"]["tags"]
    manifest = base64.standard_b64decode(parsed["source"]["target"]["manifest"])
    config = base64.standard_b64decode(parsed["source"]["target"]["config"])
    return digest, local_image_id, tags, manifest, config


# NOTE: in these examples we load from the file as bytes arrays instead of json objects to ensure that the digest computation matches and
# isn't impacted by any python re-ordering of keys or adding/removing whitespace. This should enable the output of `sha256sum <file>` to match the digests returned during this test
def upload_content(content, content_type, operation_id):

    print("Uploading {}".format(content_type))
    resp = requests.post(
        endpoint + "/imports/images/{}/{}".format(operation_id, content_type),
        data=content,
        headers=JSON_HEADER
        if content_type in ["manifest", "parent_manifest", "packages", "image_config"]
        else None,
        auth=AUTHC,
    )
    content_digest = check_response(resp).get("digest")
    return content_digest


def wait_for_image(image_digest):
    while True:
        print("Waiting for analysis completion {}".format(image_digest))
        resp = requests.get(
            endpoint + "/images/{}".format(image_digest),
            auth=AUTHC,
        )
        status = check_response(resp)[0].get("analysis_status")
        if status not in ["analyzed", "analysis_failed"]:
            time.sleep(5)
        else:
            break

    return status


def get_vuln_scan(image_digest):
    print("Getting vulnerability listing {}".format(image_digest))
    resp = requests.get(
        endpoint + "/images/{}/vuln/all".format(image_digest),
        auth=AUTHC,
    )
    return check_response(resp)


def get_policy_eval(image_digest, tag):
    print("Getting policy eval {} {}".format(image_digest, tag))
    resp = requests.get(
        endpoint + "/images/{}/check".format(image_digest),
        params={"tag": tag, "detail": True},
        auth=AUTHC,
    )
    return check_response(resp)


# Step 1: Run syft
syft_package_sbom = run_syft(tag_to_scan)

# Step 2: Initialize the operation, get an operation ID
operation_id = init_operation()

# Step 2: Upload the analysis content types
image_digest, local_image_id, tags, manifest, image_config = extract_syft_metadata(
    syft_package_sbom
)
packages_digest = upload_content(syft_package_sbom, "packages", operation_id)

if dockerfile:
    with open(dockerfile) as f:
        dockerfile_content = f.read()
    dockerfile_digest = upload_content(dockerfile_content, "dockerfile", operation_id)

else:
    dockerfile_digest = None

manifest_digest = upload_content(manifest, "manifest", operation_id)
image_config_digest = upload_content(image_config, "image_config", operation_id)

# Construct the type-to-digest map
contents = {
    "packages": packages_digest,
    "dockerfile": dockerfile_digest,
    "manifest": manifest_digest,
    #    "parent_manifest": parent_manifest_digest,
    "image_config": image_config_digest,
}

# Step 3: Complete the import by generating the import manifest which includes the conetnt reference as well as other metadata
# for the image such as digest, annotations, etc
add_payload = {
    "source": {
        "import": {
            "digest": image_digest,
            "local_image_id": local_image_id,
            "contents": contents,
            "tags": tags,
            "operation_uuid": operation_id,
        }
    },
    "annotations": {"key1": "testvalue1", "key2": "testvalue2"},
}

# Step 4: Add the image for processing the import via the analysis queue
print("Adding image/finalizing")
resp = requests.post(
    endpoint + "/images",
    json=add_payload,
    auth=AUTHC,
)
result = check_response(resp)

# Step 5: Verify the image record now exists
print("Checking image list")
resp = requests.get(
    endpoint + "/images/{digest}".format(digest=image_digest), auth=AUTHC
)
images = check_response(resp)

print("Waiting for image to finish import")
wait_for_image(image_digest)

print("Vuln scan: {}".format(get_vuln_scan(image_digest)))

for tag in tag_to_scan:
    print("Policy eval for tag {}: {}".format(tag, get_policy_eval(image_digest, tag)))

# Check for finished
print("Completed successfully!")
