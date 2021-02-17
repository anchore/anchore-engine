import base64
import json
import os
from typing import Dict, List, Union


def load_file(module_path: str, filename: str) -> str:
    """
    Given module path and filename, return file contents as string.
    Assumes file is stored in folder with same name as module at same
    path prefix.

    :param module_path: path of invoking module
    :type module_path: str
    :param filename: name of file (including extension)
    :type filename: str
    :return: file contents
    :rtype: str
    """
    directory, _ = os.path.splitext(module_path)
    filename = os.path.join(directory, filename)
    with open(filename) as f:
        text = f.read()
    return text


def extract_syft_metadata(data: str) -> Dict[str, Union[str, List[str], bytes]]:
    """
    Parse metadata from the syft output string

    :param data: syft SBOM json string
    :type data: str
    :return: dict with metadata
    :rtype: Dict[str, Union[str, List[str], bytes]]
    """
    parsed = json.loads(data)
    digest = parsed["source"]["target"]["manifestDigest"]
    local_image_id = parsed["source"]["target"]["imageID"]
    tags = parsed["source"]["target"]["tags"]
    manifest = base64.standard_b64decode(parsed["source"]["target"]["manifest"])
    image_config = base64.standard_b64decode(parsed["source"]["target"]["config"])
    return {
        "digest": digest,
        "local_image_id": local_image_id,
        "tags": tags,
        "manifest": manifest,
        "image_config": image_config,
    }
