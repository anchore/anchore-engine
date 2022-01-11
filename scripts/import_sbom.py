#!/usr/bin/env python3.8

"""
Simple example of an import flow of data output from `syft docker:nginx --output json` into Anchore. Uses syft v0.10.0 output.
"""
import asyncio
import base64
from typing import List, Tuple, Union

import httpx
import typer
import aiofiles
import aiohttp
import json

# import orjson as json  # orjson is faster and uses significantly less memory than any other json lib

JSON_HEADER = {"Content-Type": "application/json"}

app = typer.Typer()


# endpoint = "http://localhost:8088"

# Defaults... don"t use these
AUTHC_TUPLE = ("admin", "foobar")
AUTHC = aiohttp.BasicAuth("admin", "foobar")


# fix these
# endpoint = sys.argv[1]

# tag_to_scan = sys.argv[2]

# Always load from user input
# dockerfile = sys.argv[3] if len(sys.argv) > 3 else None
dockerfile = None


async def init_operation(endpoint: str):
    print("Creating import operation")
    resp_json = await post_request(f"{endpoint}/imports/images", auth=AUTHC)

    # There are other fields present, such as "expires_at" timestamp, but all we need to
    # proceed is the operation's uuid.
    return resp_json.get("uuid")


async def load_syft_data(path: str) -> bytes:
    """reads a file and returns its contents as bytes

    :param path
    :return
    """
    async with aiofiles.open(path, mode="rb") as f:
        sbom_content = await f.read()
    print(f"Loaded content from file: {path}")
    return sbom_content


def extract_syft_metadata(data):
    """
    Parse metadata from the syft output string

    :param data:
    :return:
    """
    # Parse into json to extract some info
    parsed = json.loads(str(data, "utf-8"))
    # This is the image id, use it as digest since syft doesn't get a digest from a registry
    digest = parsed["source"]["target"]["manifestDigest"]

    local_image_id = parsed["source"]["target"]["imageID"]
    tags = parsed["source"]["target"]["tags"]
    manifest = base64.standard_b64decode(parsed["source"]["target"]["manifest"])
    config = base64.standard_b64decode(parsed["source"]["target"]["config"])
    return digest, local_image_id, tags, manifest, config


# NOTE: in these examples we load from the file as bytes arrays instead of json objects to ensure that the digest
# computation matches and isn't impacted by any python re-ordering of keys or adding/removing whitespace. This should
# enable the output of `sha256sum <file>` to match the digests returned during this test
async def upload_content(endpoint: str, content: bytes, content_type, operation_id):
    print(f"Uploading {content_type}")
    sbom_json = json.loads(str(content, "utf-8"))

    resp_json = await post_request(
        f"{endpoint}/imports/images/{operation_id}/{content_type}",
        data=content,
        headers=JSON_HEADER
        if content_type in ["manifest", "parent_manifest", "packages", "image_config"]
        else None,
        auth=AUTHC,
    )
    return resp_json.get("digest")


async def wait_for_image(endpoint: str, image_digest: str, wait_interval: int = 5):
    while True:
        print(f"Waiting for analysis completion {image_digest}")
        resp_json = await get_request(f"{endpoint}/images/{image_digest}", auth=AUTHC)
        status = resp_json[0].get("analysis_status")
        if status not in ["analyzed", "analysis_failed"]:
            await asyncio.sleep(wait_interval)
        else:
            break
    return status


async def get_vuln_scan(endpoint: str, image_digest: str):
    print(f"Getting vulnerability listing {image_digest}")
    resp_json = await get_request(
        f"{endpoint}/images/{image_digest}/vuln/all",
        auth=AUTHC,
    )
    return resp_json


async def get_policy_eval(endpoint: str, image_digest: str, tag: str):
    print(f"Getting policy eval {image_digest} {tag}")
    resp_json = await get_request(
        f"{endpoint}/images/{image_digest}/check",
        params={"tag": tag, "detail": "true"},
        auth=AUTHC,
    )
    return resp_json


async def get_request(
    url: str,
    params: Union[dict, None] = None,
    auth: Tuple[str, str] = None,
    data: Union[dict, None] = None,
):
    async with aiohttp.ClientSession(auth=auth) as session:
        async with session.get(
            url, params=params, data=data, headers=JSON_HEADER
        ) as resp:
            if not resp.ok:
                raise aiohttp.ClientError(
                    f"HTTP GET request failed; response code {resp.status}."
                )
            resp_json = await resp.json()
        return resp_json


async def post_request(
    url,
    params=None,
    auth: Union[Tuple[str, str], None] = None,
    data=None,
    json_data=None,
    headers=None,
):
    async with aiohttp.ClientSession(auth=auth) as session:
        async with session.post(
            url, params=params, data=data, headers=headers, json=json_data
        ) as resp:
            if not resp.ok:
                raise aiohttp.ClientError(
                    f"HTTP POST request failed; response code {resp.status}."
                )
            resp_json = await resp.json()
        return resp_json


async def post_httpx(
    url,
    params=None,
    auth: Union[Tuple[str, str], None] = None,
    data=None,
    headers=None,
    json_data=None,
):
    async with httpx.AsyncClient() as client:
        resp = await client.post(
            url,
            follow_redirects=True,
            auth=auth,
            params=params,
            data=json_data,
            headers=headers,
        )
        resp.raise_for_status()  # will raise any 4xx or 5xx  response codes as exceptions
        return resp.json


async def import_tag(endpoint: str, tag: str):
    print(f"Begin processing {tag} from {endpoint}")
    # Step 1: Run syft
    syft_package_sbom, err = await run_syft(tag)

    # Step 2: Initialize the operation, get an operation ID
    operation_id = await init_operation(endpoint)

    # Step 3: Upload the analysis content types
    image_digest, local_image_id, tags, manifest, image_config = extract_syft_metadata(
        syft_package_sbom
    )

    packages_digest = await upload_content(
        endpoint, syft_package_sbom, "packages", operation_id
    )

    # packages_digest = await upload_content(
    #     endpoint, str(syft_package_sbom, "utf-8"), "packages", operation_id
    # )

    # if dockerfile:
    #     with open(dockerfile) as f:
    #         dockerfile_content = f.read()
    #     dockerfile_digest = upload_content(
    #         endpoint, dockerfile_content, "dockerfile", operation_id
    #     )
    #
    # else:
    #     dockerfile_digest = None

    manifest_digest = await upload_content(endpoint, manifest, "manifest", operation_id)
    image_config_digest = await upload_content(
        endpoint, image_config, "image_config", operation_id
    )

    # Construct the type-to-digest map
    contents = {
        "packages": packages_digest,
        # "dockerfile": dockerfile_digest,
        "manifest": manifest_digest,
        #    "parent_manifest": parent_manifest_digest,
        "image_config": image_config_digest,
    }

    # Step 4: Complete the import by generating the import manifest which includes the content reference as well as
    # other metadata for the image such as digest, annotations, etc
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

    # Step 5: Add the image for processing the import via the analysis queue
    print("Adding image/finalizing")
    resp_json = await post_request(
        f"{endpoint}/images", json_data=add_payload, auth=AUTHC
    )

    # Step 6: Verify the image record now exists
    print("Checking image list")
    images = await get_request(f"{endpoint}/images/{image_digest}", auth=AUTHC)

    # Note: this func blocks the async operations
    print("Waiting for image to finish import")
    wait_status = await wait_for_image(endpoint, image_digest)

    vuln_scan_result = await get_vuln_scan(endpoint, image_digest)
    print(f"Vuln scan: {vuln_scan_result}")
    policy_eval_result = await get_policy_eval(endpoint, image_digest, tag)
    print(f"Policy eval for tag {tag}: {policy_eval_result}")

    # Check for finished
    print(f"Completed {tag} successfully!")


async def run_syft(image):
    command = ["syft", f"docker:{image}", "-o", "json"]
    proc = await asyncio.create_subprocess_shell(
        " ".join(command),
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )

    stdout, stderr = await proc.communicate()
    return stdout, stderr


async def import_tags(endpoint: str, tags: List[str]):
    for fut in asyncio.as_completed([import_tag(endpoint, tag) for tag in tags]):
        try:
            result = await fut
            print(f"result: {result}")
        except Exception as err:
            # TODO: Catch better exceptions
            print(f"err: {err}")
            raise err


def main(endpoint: str, image_tags: List[str]):
    # run a method that will concurrently import all
    # of the image tags submitted as args
    asyncio.run(import_tags(endpoint, image_tags))


if __name__ == "__main__":
    typer.run(main)
